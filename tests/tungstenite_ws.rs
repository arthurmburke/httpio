//! The tokio-tungstenite backend of the `WebSocket` trait, against a local
//! tokio-tungstenite server. Runs on any host (no DPDK needed).

use std::io::ErrorKind;

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use http::{Extensions, HeaderMap, HeaderValue, StatusCode, Uri, header};
use httpio::http::errors::{HttpError, WebSocketError};
use httpio::http::websocket::{CloseFrame, Message, WebSocket};
use httpio::tungstenite::{TungsteniteClient, TungsteniteWebSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::{
    self as tg,
    handshake::server::{Request, Response},
    protocol::{CloseFrame as TgCloseFrame, frame::coding::CloseCode},
};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async};

type ServerWs = WebSocketStream<TcpStream>;

/// Binds a listener and returns its `ws://` URI.
async fn listen() -> (TcpListener, Uri) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("ws://{}/chat?room=1", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    (listener, uri)
}

/// Accepts one connection, selecting `protocol` if given, and hands the
/// handshake request to `check`.
// tungstenite's callback signature fixes the (large) error-response type.
#[allow(clippy::result_large_err)]
async fn accept(
    listener: &TcpListener,
    protocol: Option<&'static str>,
    check: impl FnOnce(&Request) + Unpin,
) -> ServerWs {
    let (stream, _) = listener.accept().await.unwrap();
    accept_hdr_async(stream, |req: &Request, mut resp: Response| {
        check(req);
        if let Some(p) = protocol {
            resp.headers_mut()
                .insert(header::SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static(p));
        }
        resp.headers_mut()
            .insert(header::SET_COOKIE, HeaderValue::from_static("session=abc"));
        Ok(resp)
    })
    .await
    .unwrap()
}

/// Echoes every data message until the client closes.
async fn echo(mut ws: ServerWs) {
    while let Some(Ok(msg)) = ws.next().await {
        if msg.is_text() || msg.is_binary() {
            ws.send(msg).await.unwrap();
        }
    }
}

async fn open(uri: Uri, headers: HeaderMap) -> Result<TungsteniteWebSocket, WebSocketError> {
    TungsteniteWebSocket::open(&TungsteniteClient::new(), uri, headers, Extensions::new()).await
}

/// Written only against the trait: the same code runs over the DPDK client.
async fn roundtrip<W: WebSocket>(client: &W::Client, uri: Uri) -> Result<(), WebSocketError> {
    let mut ws = W::open(client, uri, HeaderMap::new(), Extensions::new()).await?;
    ws.send(Message::Text("hello".into())).await?;
    assert_eq!(ws.next().await, Some(Ok(Message::Text("hello".into()))));
    ws.send(Message::Binary(Bytes::from_static(&[0, 1, 2, 255])))
        .await?;
    assert_eq!(
        ws.next().await,
        Some(Ok(Message::Binary(Bytes::from_static(&[0, 1, 2, 255]))))
    );
    ws.close().await
}

#[tokio::test]
async fn generic_roundtrip_over_trait() {
    let (listener, uri) = listen().await;
    let server = tokio::spawn(async move { echo(accept(&listener, None, |_| {}).await).await });
    roundtrip::<TungsteniteWebSocket>(&TungsteniteClient::new(), uri)
        .await
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn handshake_headers_protocol_and_response() {
    let (listener, uri) = listen().await;
    let server = tokio::spawn(async move {
        let ws = accept(&listener, Some("chat.v2"), |req| {
            assert_eq!(req.uri().path_and_query().unwrap(), "/chat?room=1");
            assert_eq!(req.headers()[header::AUTHORIZATION], "Bearer t");
            // The caller's bogus key was replaced by a real one.
            assert_ne!(req.headers()[header::SEC_WEBSOCKET_KEY], "bogus");
            assert_eq!(req.headers()[header::SEC_WEBSOCKET_VERSION], "13");
        })
        .await;
        echo(ws).await
    });

    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer t"));
    headers.insert(header::SEC_WEBSOCKET_KEY, HeaderValue::from_static("bogus"));
    headers.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static("chat.v1, chat.v2"),
    );
    let mut ws = open(uri, headers).await.unwrap();
    assert_eq!(ws.protocol(), Some("chat.v2"));
    assert_eq!(ws.handshake().status, StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(ws.handshake().headers[header::SET_COOKIE], "session=abc");
    ws.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn ping_is_surfaced_and_auto_ponged() {
    let (listener, uri) = listen().await;
    let server = tokio::spawn(async move {
        let mut ws = accept(&listener, None, |_| {}).await;
        ws.send(tg::Message::Ping(Bytes::from_static(b"p")))
            .await
            .unwrap();
        // The client's next read flushes the queued Pong.
        let pong = ws.next().await.unwrap().unwrap();
        assert_eq!(pong, tg::Message::Pong(Bytes::from_static(b"p")));
        ws.send(tg::Message::Text("done".into())).await.unwrap();
        echo(ws).await
    });

    let mut ws = open(uri, HeaderMap::new()).await.unwrap();
    assert_eq!(
        ws.next().await,
        Some(Ok(Message::Ping(Bytes::from_static(b"p"))))
    );
    assert_eq!(ws.next().await, Some(Ok(Message::Text("done".into()))));
    ws.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn server_close_is_echoed_then_stream_ends() {
    let (listener, uri) = listen().await;
    let server = tokio::spawn(async move {
        let mut ws = accept(&listener, None, |_| {}).await;
        ws.close(Some(TgCloseFrame {
            code: CloseCode::Normal,
            reason: "bye".into(),
        }))
        .await
        .unwrap();
        // The client's echoed Close completes the handshake.
        assert!(matches!(ws.next().await, Some(Ok(tg::Message::Close(_)))));
    });

    let mut ws = open(uri, HeaderMap::new()).await.unwrap();
    assert_eq!(
        ws.next().await,
        Some(Ok(Message::Close(Some(CloseFrame {
            code: 1000,
            reason: "bye".into()
        }))))
    );
    assert_eq!(ws.next().await, None);
    assert_eq!(
        ws.send(Message::Text("late".into())).await,
        Err(WebSocketError::SendAfterClose)
    );
    server.await.unwrap();
}

#[tokio::test]
async fn client_close_frame_reaches_server() {
    let (listener, uri) = listen().await;
    let server = tokio::spawn(async move {
        let mut ws = accept(&listener, None, |_| {}).await;
        let close = ws.next().await.unwrap().unwrap();
        assert_eq!(
            close,
            tg::Message::Close(Some(TgCloseFrame {
                code: CloseCode::Away,
                reason: "going".into()
            }))
        );
    });

    let mut ws = open(uri, HeaderMap::new()).await.unwrap();
    ws.send(Message::Close(Some(CloseFrame {
        code: 1001,
        reason: "going".into(),
    })))
    .await
    .unwrap();
    assert_eq!(
        ws.send(Message::Text("late".into())).await,
        Err(WebSocketError::SendAfterClose)
    );
    server.await.unwrap();
}

#[tokio::test]
async fn eof_without_close_is_unclean() {
    let (listener, uri) = listen().await;
    let server = tokio::spawn(async move {
        let ws = accept(&listener, None, |_| {}).await;
        drop(ws.into_inner()); // drop the TCP connection, no Close frame
    });

    let mut ws = open(uri, HeaderMap::new()).await.unwrap();
    server.await.unwrap();
    assert_eq!(ws.next().await, Some(Err(WebSocketError::UncleanClose)));
}

#[tokio::test]
async fn oversized_control_frame_rejected_locally() {
    let (listener, uri) = listen().await;
    let server = tokio::spawn(async move { echo(accept(&listener, None, |_| {}).await).await });

    let mut ws = open(uri, HeaderMap::new()).await.unwrap();
    assert_eq!(
        ws.send(Message::Ping(Bytes::from(vec![0; 126]))).await,
        Err(WebSocketError::ControlFrameTooLarge)
    );
    ws.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn non_101_status_is_reported() {
    let (listener, uri) = listen().await;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    assert_eq!(
        open(uri, HeaderMap::new()).await.err(),
        Some(WebSocketError::UnexpectedStatus(StatusCode::NOT_FOUND))
    );
    server.await.unwrap();
}

#[tokio::test]
async fn unsupported_scheme_and_refused_connect() {
    assert_eq!(
        open("http://127.0.0.1/".parse().unwrap(), HeaderMap::new())
            .await
            .err(),
        Some(WebSocketError::UnsupportedScheme)
    );

    // Bind then drop to get a port nothing is listening on.
    let (listener, uri) = listen().await;
    drop(listener);
    assert_eq!(
        open(uri, HeaderMap::new()).await.err(),
        Some(WebSocketError::Upgrade(HttpError::Connect(
            ErrorKind::ConnectionRefused
        )))
    );
}
