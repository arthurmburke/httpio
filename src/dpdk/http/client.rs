//! The HTTP client: HTTPS via rustls (webpki roots + custom CAs, ALPN),
//! HTTP/1.1 via the zero-copy codec in [`h1`] (plain and over TLS),
//! HTTP/2 via the multiplexing codec in [`h2`], and protocol upgrades via
//! hyper's low-level `client::conn` API, all over `TcpStream`.
//!
//! The request/response API uses the `http` crate's types directly:
//! `http::Request<B>` in, `http::Response<R>` out, with bodies encoded and
//! decoded by [`codec`]; a [`ByteStream`] on either side is streamed
//! rather than buffered.
//!
//! Connection reuse: HTTP/2 connections are pooled per origin
//! (host, port) and multiplexed -- [`h2::SendRequest`] is `Clone`, so
//! any number of requests, buffered or streamed, share one TCP+TLS
//! connection until the server closes it (there is no idle timeout on our
//! side). An HTTP/1.1 connection carries one request at a time; when its
//! response has been read it is kept, per origin, and the next HTTP/1.1
//! request to that origin takes it instead of connecting again (corked
//! requests included -- the connection is corked afresh for each). A
//! connection the server closed while it was idle is noticed and dropped
//! when it is next looked at. One it closes just as a request is sent on
//! it fails that request, which is not sent again here: the server may
//! have acted on it. A reused connection keeps the `nodelay` setting it
//! was opened with.
//!
//! A buffered request the server did not process -- it refused the
//! stream, or announced it was going away before reaching it
//! ([`h2::H2Error::Refused`]) -- is sent once more, on a new connection
//! if that one is closing. A streamed request is not: its body may have
//! been consumed.

use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;
use http::request::Parts;
use http::{HeaderValue, Method, Request, Response, Uri, Version, header};
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::core::hashmap::HashMap;
use crate::dpdk::http::{h1, h2};
use crate::dpdk::tcp::stream::{FlushHandle, TcpOptions, TcpStream};
use crate::dpdk::tcp::worker::WorkerHandle;
use crate::dpdk::tls::{TlsConnector, TlsStream};
use crate::http::codec::{self, ByteStream, Empty, EncodedBody};
use crate::http::errors::HttpError;

/// Origin key for the h2 pool: (host, port). Scheme is implicit (only
/// `https` + ALPN produces an h2 connection), and corked requests never
/// reach the pool (they force h1), so transport options aren't part of
/// the key.
// Nested maps permit borrowed host lookups without constructing an origin key.
type H2Pool = Arc<AsyncMutex<HashMap<String, HashMap<u16, h2::SendRequest<TlsStream>>>>>;

/// The idle HTTP/1.1 connections, per origin (host, port), over one kind
/// of transport. Bodies return connections to it as they finish, from
/// inside a poll, so it is behind a plain mutex, held only for a lookup.
type H1Pool<T> = Arc<Mutex<HashMap<String, HashMap<u16, Arc<h1::Idle<T>>>>>>;

/// The idle set for an origin, made on first use.
fn idle_connections<T>(pool: &H1Pool<T>, host: &str, port: u16) -> Arc<h1::Idle<T>> {
    let mut pool = pool.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(idle) = pool.get(host).and_then(|ports| ports.get(&port)) {
        return idle.clone();
    }
    pool.entry(host.to_owned())
        .or_default()
        .entry(port)
        .or_default()
        .clone()
}

/// First port of the ephemeral range handed out by the client.
const EPHEMERAL_FIRST: u16 = 49152;
/// Last (inclusive) port of the ephemeral range.
const EPHEMERAL_LAST: u16 = 65535;
/// How many fresh local ports `dial` tries when the worker reports the
/// 4-tuple already in use, before giving up with `Connect(AddrInUse)`.
const DIAL_PORT_ATTEMPTS: usize = 64;

/// A response body still on the wire: the HTTP/2 codec's (see [`h2`]) or
/// the HTTP/1.1 codec's (see [`h1`]), over plain TCP or over TLS. An h1
/// body owns its connection, so the connection lives exactly as long as
/// the body is read; an h2 body is one stream of a pooled connection.
enum ResponseBody {
    H2(h2::Body<TlsStream>),
    H1(h1::Body<TcpStream>),
    H1Tls(h1::Body<TlsStream>),
}

/// Atomically takes the next port from `cursor`, wrapping from
/// `EPHEMERAL_LAST` back to `EPHEMERAL_FIRST`. A cursor value outside the
/// range is treated as `EPHEMERAL_FIRST`. Because the successor is computed
/// inside one `fetch_update`, concurrent callers never receive the same
/// port from a single pass over the range.
fn next_ephemeral_port(cursor: &AtomicU16) -> u16 {
    let in_range = |p: u16| {
        if (EPHEMERAL_FIRST..=EPHEMERAL_LAST).contains(&p) {
            p
        } else {
            EPHEMERAL_FIRST
        }
    };
    let prev = cursor
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
            let port = in_range(cur);
            Some(if port == EPHEMERAL_LAST {
                EPHEMERAL_FIRST
            } else {
                port + 1
            })
        })
        .expect("closure always returns Some");
    in_range(prev)
}

/// Classifies a request URI scheme (ASCII case-insensitive) for
/// `http`/`https` requests: `Ok(true)` for TLS (`https`), `Ok(false)` for
/// plain `http`, and `UnsupportedScheme` for anything else. An absent
/// scheme is treated as `http`. (`http::Uri` already lowercases `http` and
/// `https`, but this does not rely on that.)
fn http_scheme_is_tls(scheme: Option<&str>) -> Result<bool, HttpError> {
    match scheme {
        None => Ok(false),
        Some(s) if s.eq_ignore_ascii_case("https") => Ok(true),
        Some(s) if s.eq_ignore_ascii_case("http") => Ok(false),
        Some(_) => Err(HttpError::UnsupportedScheme),
    }
}

fn normalized_host(host: &str) -> Cow<'_, str> {
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(host.to_ascii_lowercase())
    } else {
        Cow::Borrowed(host)
    }
}

pub mod builder {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU16;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rustls::RootCertStore;
    use tokio::sync::Mutex;

    use super::Client;

    use crate::core::hashmap::HashMap;
    use crate::dpdk::tcp::worker::WorkerHandle;
    use crate::dpdk::tls::TlsConnector;
    use crate::http::errors::BuilderError;

    pub struct Builder {
        roots: RootCertStore,
        resolve: HashMap<String, Ipv4Addr>,
    }

    impl Default for Builder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Builder {
        /// Starts with the Mozilla (webpki) root set; add custom CAs on top.
        pub fn new() -> Self {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Self {
                roots,
                resolve: HashMap::default(),
            }
        }

        /// Trusts every CA certificate in a PEM bundle (in addition to the
        /// default roots). Returns an error if the PEM parses but contains
        /// no usable certificate.
        pub fn add_root_ca_pem(mut self, pem: &[u8]) -> Result<Self, BuilderError> {
            let mut reader = std::io::Cursor::new(pem);
            let mut added = 0usize;
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|_| BuilderError::MalformedPem)?;
                self.roots
                    .add(cert)
                    .map_err(|_| BuilderError::InvalidCertificate)?;
                added += 1;
            }
            if added == 0 {
                return Err(BuilderError::NoCertificates);
            }
            Ok(self)
        }

        pub fn add_root_ca_pem_file(self, path: &str) -> Result<Self, BuilderError> {
            let pem = std::fs::read(path).map_err(|e| BuilderError::ReadFile(e.kind()))?;
            self.add_root_ca_pem(&pem)
        }

        /// Maps a hostname to an IPv4 address (curl `--resolve` style). The
        /// hostname is still used for SNI and certificate validation; only
        /// the TCP connection goes to `ip`.
        pub fn resolve(mut self, host: &str, ip: Ipv4Addr) -> Self {
            self.resolve.insert(host.to_ascii_lowercase(), ip);
            self
        }

        pub fn build(self, worker: WorkerHandle) -> Client {
            let base_config = rustls::ClientConfig::builder()
                .with_root_certificates(self.roots)
                .with_no_client_auth();
            // Offer h2 first; the server's ALPN choice decides which hyper
            // connection type we speak.
            let mut tls_config = base_config.clone();
            tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            // Corked requests hold their final segment for a manual flush,
            // which doesn't compose with a shared multiplexed h2 connection;
            // they dial with an h1-only ALPN offer instead.
            let mut tls_h1_config = base_config;
            tls_h1_config.alpn_protocols = vec![b"http/1.1".to_vec()];

            // Seed the ephemeral port cursor from the clock so back-to-back
            // process runs don't collide with the peer's TIME_WAIT state for
            // the previous run's 4-tuple.
            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u16;
            let next_port = 49152 + (seed % 16000);

            Client {
                worker,
                tls: TlsConnector::from(Arc::new(tls_config)),
                tls_h1: TlsConnector::from(Arc::new(tls_h1_config)),
                resolve: self.resolve,
                next_port: Arc::new(AtomicU16::new(next_port)),
                h2_pool: Arc::new(Mutex::new(HashMap::default())),
                h1_tls_pool: Default::default(),
                h1_plain_pool: Default::default(),
            }
        }
    }
}

#[derive(Clone)]
pub struct Client {
    worker: WorkerHandle,
    /// ALPN offers h2 + http/1.1 (server chooses).
    tls: TlsConnector,
    /// ALPN offers http/1.1 only, used for corked requests (a manually
    /// held tail is incompatible with a shared multiplexed h2 connection).
    tls_h1: TlsConnector,
    resolve: HashMap<String, Ipv4Addr>,
    next_port: Arc<AtomicU16>,
    h2_pool: H2Pool,
    /// Idle `https` HTTP/1.1 connections, whichever ALPN offer they were
    /// opened with.
    h1_tls_pool: H1Pool<TlsStream>,
    /// Idle plain `http` connections.
    h1_plain_pool: H1Pool<TcpStream>,
}

impl Client {
    /// Convenience GET with an [`Empty`] body; the response is decoded into
    /// `R` from its `Content-Type`. See [`request`](Self::request).
    pub async fn get<R: DeserializeOwned + 'static>(
        &self,
        url: &str,
    ) -> Result<Response<R>, HttpError> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Empty)
            .map_err(|_| HttpError::MalformedUri)?;
        self.request(request).await
    }

    /// Sends one request, encoding the body `B` to bytes for the request's
    /// `Content-Type` and decoding the response body into `R` from the
    /// response's `Content-Type` (see [`codec`](crate::http::codec)).
    ///
    /// The request URI must be absolute (scheme + host) since it's also what
    /// decides where to connect. For `https` the protocol (HTTP/1.1 vs
    /// HTTP/2) follows the server's ALPN choice; plain `http` speaks
    /// HTTP/1.1. HTTP/2 connections are reused per origin.
    ///
    /// Transport tuning: insert a [`TcpOptions`] into the request's
    /// extensions to control TCP_NODELAY / corking for the connection this
    /// request uses (consumed here, not forwarded to the server).
    pub async fn request<B, R>(&self, request: Request<B>) -> Result<Response<R>, HttpError>
    where
        B: Serialize + 'static,
        R: DeserializeOwned + 'static,
    {
        let (parts, body) = request.into_parts();
        let response = match codec::encode(parts.headers.get(header::CONTENT_TYPE), body)? {
            EncodedBody::Full(bytes) => {
                self.send_buffered(Request::from_parts(parts, bytes))
                    .await?
            }
            // A ByteStream body is sent chunk-by-chunk as it is produced.
            EncodedBody::Stream(stream) => self.send_stream(parts, stream).await?,
        };

        // Each codec hands a `ByteStream` target the body unbuffered and
        // collects and decodes anything else for its `Content-Type`.
        let (parts, body) = response.into_parts();
        match body {
            ResponseBody::H2(body) => {
                h2::into_typed_response(Response::from_parts(parts, body)).await
            }
            ResponseBody::H1(body) => {
                h1::into_typed_response(Response::from_parts(parts, body)).await
            }
            ResponseBody::H1Tls(body) => {
                h1::into_typed_response(Response::from_parts(parts, body)).await
            }
        }
    }

    /// Sends a request whose body is already fully-buffered bytes and
    /// returns the raw response (body uncollected) -- the transport pipeline
    /// the generic [`request`](Self::request) wraps.
    async fn send_buffered(
        &self,
        request: Request<Bytes>,
    ) -> Result<Response<ResponseBody>, HttpError> {
        let (mut parts, body) = request.into_parts();
        let tcp_options = parts.extensions.remove::<TcpOptions>().unwrap_or_default();
        let flush_handle = parts.extensions.remove::<FlushHandle>();

        if flush_handle.is_none() && tcp_options.cork {
            return Err(HttpError::CorkWithoutFlushHandle);
        }
        // Called off before it began: no connection is taken for it.
        if flush_handle
            .as_ref()
            .is_some_and(FlushHandle::is_terminated)
        {
            return Err(HttpError::Connect(std::io::ErrorKind::ConnectionAborted));
        }

        let uri = parts.uri.clone();
        let is_https = http_scheme_is_tls(uri.scheme_str())?;
        let host = normalized_host(uri.host().ok_or(HttpError::MissingHost)?);
        let port = parts
            .uri
            .port_u16()
            .unwrap_or(if is_https { 443 } else { 80 });

        if is_https {
            // Corked requests can't share a multiplexed h2 connection, so
            // they always take the h1 path, each on a connection it has to
            // itself for as long as it lasts.
            if tcp_options.cork {
                let (tls, idle) = self
                    .corked_tls_h1(&host, port, tcp_options, flush_handle.as_ref())
                    .await?;
                return send_tls_h1(tls, parts, EncodedBody::Full(body), &host, port, idle).await;
            }

            // One more attempt if the server did not process the first:
            // nothing of the request took effect, so sending it again
            // cannot repeat anything.
            let mut retried = false;
            loop {
                let connection = self
                    .connect_tls(&host, port, tcp_options, flush_handle.as_ref())
                    .await?;
                let send_request = match connection {
                    TlsConnection::H2(send_request) => send_request,
                    TlsConnection::H1(tls, idle) => {
                        return send_tls_h1(
                            *tls,
                            parts,
                            EncodedBody::Full(body),
                            &host,
                            port,
                            idle,
                        )
                        .await;
                    }
                };
                let body = EncodedBody::Full(body.clone());
                match send_h2_on(&send_request, &parts, body).await {
                    Err(error) if !retried && is_refused(&error) => retried = true,
                    result => return result.map_err(HttpError::from),
                }
            }
        } else {
            let (tcp, idle) = self
                .plain_h1(&host, port, tcp_options, flush_handle.as_ref())
                .await?;
            send_plain_h1(tcp, parts, EncodedBody::Full(body), &host, port, idle).await
        }
    }

    /// Sends a request whose body is a [`ByteStream`], chunk-by-chunk as the
    /// stream yields: as DATA frames on a pooled HTTP/2 connection when
    /// the origin speaks it, else with chunked transfer-encoding on an
    /// HTTP/1.1 connection of its own (the total length being unknown).
    ///
    /// A corked request takes the HTTP/1.1 path, as a buffered one does:
    /// the held tail is released by the caller's `FlushHandle`.
    async fn send_stream(
        &self,
        mut parts: Parts,
        body: ByteStream<'static>,
    ) -> Result<Response<ResponseBody>, HttpError> {
        let tcp_options = parts.extensions.remove::<TcpOptions>().unwrap_or_default();
        let flush_handle = parts.extensions.remove::<FlushHandle>();

        if flush_handle.is_none() && tcp_options.cork {
            return Err(HttpError::CorkWithoutFlushHandle);
        }
        // Called off before it began: no connection is taken for it.
        if flush_handle
            .as_ref()
            .is_some_and(FlushHandle::is_terminated)
        {
            return Err(HttpError::Connect(std::io::ErrorKind::ConnectionAborted));
        }

        let uri = parts.uri.clone();
        let is_https = http_scheme_is_tls(uri.scheme_str())?;
        let host = normalized_host(uri.host().ok_or(HttpError::MissingHost)?);
        let port = parts
            .uri
            .port_u16()
            .unwrap_or(if is_https { 443 } else { 80 });

        if is_https && !tcp_options.cork {
            let connection = self
                .connect_tls(&host, port, tcp_options, flush_handle.as_ref())
                .await?;
            return match connection {
                TlsConnection::H2(send_request) => {
                    send_h2_on(&send_request, &parts, EncodedBody::Stream(body))
                        .await
                        .map_err(HttpError::from)
                }
                TlsConnection::H1(tls, idle) => {
                    send_tls_h1(*tls, parts, EncodedBody::Stream(body), &host, port, idle).await
                }
            };
        }

        if is_https {
            let (tls, idle) = self
                .corked_tls_h1(&host, port, tcp_options, flush_handle.as_ref())
                .await?;
            send_tls_h1(tls, parts, EncodedBody::Stream(body), &host, port, idle).await
        } else {
            let (tcp, idle) = self
                .plain_h1(&host, port, tcp_options, flush_handle.as_ref())
                .await?;
            send_plain_h1(tcp, parts, EncodedBody::Stream(body), &host, port, idle).await
        }
    }

    /// A corked `https` HTTP/1.1 connection, with where it goes when its
    /// response has been read: one the origin left idle if there is one,
    /// else a new one offering only `http/1.1`. Corked here, the TLS
    /// handshake being over either way, for `flush_handle` to release.
    async fn corked_tls_h1(
        &self,
        host: &str,
        port: u16,
        options: TcpOptions,
        flush_handle: Option<&FlushHandle>,
    ) -> Result<(TlsStream, Arc<h1::Idle<TlsStream>>), HttpError> {
        let idle = idle_connections(&self.h1_tls_pool, host, port);
        let tls = match idle.take() {
            Some(mut tls) => {
                tls.set_flush_handle(flush_handle);
                tls
            }
            None => {
                let tcp = self.dial(host, port, options, flush_handle).await?;
                let server_name = ServerName::try_from(host)
                    .map_err(|_| HttpError::InvalidHost)?
                    .to_owned();
                self.tls_h1
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| HttpError::TlsHandshake(e.kind()))?
            }
        };
        tls.tcp().request_cork();
        Ok((tls, idle))
    }

    /// A plain `http` connection, with where it goes when its response has
    /// been read: one the origin left idle if there is one, else a new one.
    /// Corked if `options` say so; plain HTTP has no handshake to wait for.
    async fn plain_h1(
        &self,
        host: &str,
        port: u16,
        options: TcpOptions,
        flush_handle: Option<&FlushHandle>,
    ) -> Result<(TcpStream, Arc<h1::Idle<TcpStream>>), HttpError> {
        let idle = idle_connections(&self.h1_plain_pool, host, port);
        let tcp = match idle.take() {
            Some(mut tcp) => {
                tcp.set_flush_handle(flush_handle);
                tcp
            }
            None => self.dial(host, port, options, flush_handle).await?,
        };
        if options.cork {
            tcp.request_cork();
        }
        Ok((tcp, idle))
    }

    /// Sends `request` over a fresh HTTP/1.1 connection with protocol-
    /// upgrade support and returns the raw response (body uncollected), so
    /// a `101 Switching Protocols` response keeps its `OnUpgrade` slot for
    /// `hyper::upgrade::on`. Used by the WebSocket client (`ws.rs`).
    ///
    /// Schemes: `ws`/`http` dial plain TCP; `wss`/`https` dial through the
    /// h1-only TLS connector (upgrades don't exist on multiplexed h2).
    /// Connections are never pooled and never corked -- a held tail would
    /// stall the interactive protocol the upgrade hands over to. A
    /// `TcpOptions` extension asking to cork is rejected; its `nodelay`
    /// choice is honored (default on).
    pub async fn h1_upgrade_request(
        &self,
        request: Request<Bytes>,
    ) -> Result<Response<hyper::body::Incoming>, HttpError> {
        let (mut parts, body) = request.into_parts();
        let caller_options = parts.extensions.remove::<TcpOptions>();
        if caller_options.is_some_and(|options| options.cork) {
            return Err(HttpError::CorkOnUpgrade);
        }
        let tcp_options = TcpOptions {
            nodelay: caller_options.is_none_or(|options| options.nodelay),
            cork: false,
        };

        let uri = parts.uri.clone();
        let scheme = uri.scheme_str().unwrap_or("ws");
        let tls = scheme.eq_ignore_ascii_case("wss") || scheme.eq_ignore_ascii_case("https");
        let host = normalized_host(uri.host().ok_or(HttpError::MissingHost)?);
        let default_port = if tls { 443 } else { 80 };
        let port = parts.uri.port_u16().unwrap_or(default_port);

        rewrite_to_origin_form(&mut parts, &host, port, default_port)?;
        let request = Request::from_parts(parts, Full::new(body));

        let tcp = self.dial(&host, port, tcp_options, None).await?;
        if tls {
            let server_name = ServerName::try_from(host.as_ref())
                .map_err(|_| HttpError::InvalidHost)?
                .to_owned();
            let tls_stream = self
                .tls_h1
                .connect(server_name, tcp)
                .await
                .map_err(|e| HttpError::TlsHandshake(e.kind()))?;
            send_h1_upgradable(tls_stream, request).await
        } else {
            send_h1_upgradable(tcp, request).await
        }
    }

    /// A connection for an uncorked `https` request: the origin's pooled
    /// HTTP/2 connection if it has a live one, else an HTTP/1.1 connection
    /// it left idle, else a new connection, which is pooled if ALPN chose
    /// `h2` and handed over as a TLS stream for HTTP/1.1 if not.
    async fn connect_tls(
        &self,
        host: &str,
        port: u16,
        options: TcpOptions,
        flush_handle: Option<&FlushHandle>,
    ) -> Result<TlsConnection, HttpError> {
        // Fast path: multiplex onto an existing h2 connection.
        if let Some(send_request) = self.pooled_h2(host, port).await {
            return Ok(TlsConnection::H2(send_request));
        }
        let idle = idle_connections(&self.h1_tls_pool, host, port);
        if let Some(mut tls) = idle.take() {
            tls.set_flush_handle(flush_handle);
            return Ok(TlsConnection::H1(Box::new(tls), idle));
        }
        let tcp = self.dial(host, port, options, flush_handle).await?;
        let server_name = ServerName::try_from(host)
            .map_err(|_| HttpError::InvalidHost)?
            .to_owned();
        let tls = self
            .tls
            .connect(server_name, tcp)
            .await
            .map_err(|e| HttpError::TlsHandshake(e.kind()))?;
        let mut tls = tls;
        if tls.alpn_protocol() != Some(b"h2".as_slice()) {
            return Ok(TlsConnection::H1(Box::new(tls), idle));
        }
        // From here the connection is shared by every request to the
        // origin: the one that happened to open it must not be able to
        // end it through its flush handle.
        tls.set_flush_handle(None);
        let send_request = handshake_h2(tls);
        // Pool a clone; on a race where two tasks dialed the same origin
        // concurrently, last-in wins and the loser's connection just
        // serves its own request and then idles until the server reaps it.
        self.h2_pool
            .lock()
            .await
            .entry(host.to_owned())
            .or_default()
            .insert(port, send_request.clone());
        Ok(TlsConnection::H2(send_request))
    }

    async fn dial(
        &self,
        host: &str,
        port: u16,
        options: TcpOptions,
        flush_handle: Option<&FlushHandle>,
    ) -> Result<TcpStream, HttpError> {
        let ip = self.resolve_ip(host)?;
        // The cursor doesn't know which ports are still in use (live or
        // TIME_WAIT), so the worker may refuse a 4-tuple with `AddrInUse`;
        // retry with a fresh port a bounded number of times.
        let mut last = std::io::ErrorKind::AddrInUse;
        for _ in 0..DIAL_PORT_ATTEMPTS {
            let local_port = self.alloc_ephemeral_port();
            match TcpStream::connect(&self.worker, ip, port, local_port, options, flush_handle)
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => last = e.kind(),
                Err(e) => return Err(HttpError::Connect(e.kind())),
            }
        }
        Err(HttpError::Connect(last))
    }

    /// Checks out a clone of the pooled h2 `SendRequest` for this origin
    /// if the underlying connection still takes new streams; evicts dead
    /// entries.
    async fn pooled_h2(&self, host: &str, port: u16) -> Option<h2::SendRequest<TlsStream>> {
        let mut pool = self.h2_pool.lock().await;
        let ports = pool.get_mut(host)?;
        let send_request = ports.get_mut(&port)?;
        if send_request.is_closed() {
            ports.remove(&port);
            if ports.is_empty() {
                pool.remove(host);
            }
            return None;
        }
        Some(send_request.clone())
    }

    fn resolve_ip(&self, host: &str) -> Result<Ipv4Addr, HttpError> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(ip);
        }
        self.resolve
            .get(host)
            .copied()
            .ok_or(HttpError::UnresolvedHost)
    }

    fn alloc_ephemeral_port(&self) -> u16 {
        next_ephemeral_port(&self.next_port)
    }
}

impl crate::http::client::HttpClient for Client {
    async fn request<B: Serialize + Send + 'static, R: DeserializeOwned + 'static>(
        &self,
        request: Request<B>,
    ) -> Result<Response<R>, HttpError> {
        Client::request(self, request).await
    }
}

/// HTTP/1.1 wants an origin-form request target plus a Host header
/// (hyper's low-level conn API doesn't add one); rewrites the parts in
/// place, preserving the caller's method/headers/extensions.
/// `default_port` is elided from the Host header per convention.
fn rewrite_to_origin_form(
    parts: &mut Parts,
    host: &str,
    port: u16,
    default_port: u16,
) -> Result<(), HttpError> {
    let origin_form: Uri = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .parse()
        .map_err(|_| HttpError::MalformedUri)?;
    parts.uri = origin_form;
    parts.version = Version::HTTP_11;
    if !parts.headers.contains_key(header::HOST) {
        let host_value = if port == default_port {
            HeaderValue::from_str(host)
        } else {
            HeaderValue::try_from(format!("{host}:{port}"))
        }
        .map_err(|_| HttpError::InvalidHost)?;
        parts.headers.insert(header::HOST, host_value);
    }
    Ok(())
}

/// Plain `http` over the zero-copy HTTP/1.1 codec ([`h1`]) instead of hyper:
/// the head is built in place and body `Bytes` move to and from the
/// connection without copies.
async fn send_plain_h1(
    tcp: TcpStream,
    mut parts: Parts,
    body: EncodedBody,
    host: &str,
    port: u16,
    idle: Arc<h1::Idle<TcpStream>>,
) -> Result<Response<ResponseBody>, HttpError> {
    rewrite_to_origin_form(&mut parts, host, port, 80)?;
    let response = h1::send_over_tcp_reusing(tcp, parts, body, idle).await?;
    Ok(response.map(ResponseBody::H1))
}

/// `https` HTTP/1.1 over the same codec, exchanging plaintext `Bytes` with
/// the TLS stream. When the response body ends the connection goes to
/// `idle` for the next request, or is dropped if it cannot carry one.
async fn send_tls_h1(
    tls: TlsStream,
    mut parts: Parts,
    body: EncodedBody,
    host: &str,
    port: u16,
    idle: Arc<h1::Idle<TlsStream>>,
) -> Result<Response<ResponseBody>, HttpError> {
    rewrite_to_origin_form(&mut parts, host, port, 443)?;
    let response = h1::send_over_tls_reusing(tls, parts, body, idle).await?;
    Ok(response.map(ResponseBody::H1Tls))
}

/// HTTP/1.1 through hyper, for protocol upgrades only: the connection task is
/// driven with `with_upgrades()` (so a `101 Switching Protocols` response
/// can hand the underlying connection to `hyper::upgrade::on`) and the
/// response is returned raw, body uncollected.
async fn send_h1_upgradable<T>(
    io: T,
    request: Request<Full<Bytes>>,
) -> Result<Response<hyper::body::Incoming>, HttpError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut send_request, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|_| HttpError::Protocol)?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    send_request
        .send_request(request)
        .await
        .map_err(|_| HttpError::Protocol)
}

/// Starts an HTTP/2 connection over `tls` and spawns its driver task. The
/// returned `SendRequest` is the poolable, clonable multiplexing handle;
/// the connection lives until the server ends it or every handle and
/// response is gone. The connection preface leaves with the first request.
fn handshake_h2(tls: TlsStream) -> h2::SendRequest<TlsStream> {
    let (send_request, connection) = h2::handshake(tls);
    tokio::spawn(async move {
        let _ = connection.await;
    });
    send_request
}

/// What [`Client::connect_tls`] connected to.
enum TlsConnection {
    /// An HTTP/2 connection, pooled.
    H2(h2::SendRequest<TlsStream>),
    /// A TLS stream to a server that chose HTTP/1.1, new or left idle by
    /// an earlier request, and the idle set it returns to.
    H1(Box<TlsStream>, Arc<h1::Idle<TlsStream>>),
}

/// Sends one request as a new stream on an h2 connection. HTTP/2 derives
/// `:scheme`, `:authority` and `:path` from the absolute URI the caller
/// supplied. `parts` is borrowed so the caller can send it again.
async fn send_h2_on(
    send_request: &h2::SendRequest<TlsStream>,
    parts: &Parts,
    body: EncodedBody,
) -> Result<Response<ResponseBody>, h2::SendError> {
    let response = send_request
        .send_ref(parts, body)
        .map_err(h2::SendError::Request)?
        .await?;
    Ok(response.map(ResponseBody::H2))
}

/// Whether the server left the request unprocessed, so that sending it
/// again repeats nothing.
fn is_refused(error: &h2::SendError) -> bool {
    matches!(error, h2::SendError::H2(h2::H2Error::Refused))
}

#[cfg(test)]
mod allocation_tests {
    use super::*;

    #[test]
    fn scheme_classification_is_case_insensitive_and_strict() {
        assert_eq!(http_scheme_is_tls(Some("https")), Ok(true));
        assert_eq!(http_scheme_is_tls(Some("HTTPS")), Ok(true));
        assert_eq!(http_scheme_is_tls(Some("HtTp")), Ok(false));
        assert_eq!(http_scheme_is_tls(Some("http")), Ok(false));
        assert_eq!(http_scheme_is_tls(None), Ok(false));
        for bad in ["ftp", "ws", "wss", "httpss", ""] {
            assert_eq!(
                http_scheme_is_tls(Some(bad)),
                Err(HttpError::UnsupportedScheme)
            );
        }
        // End to end through http::Uri.
        let uri: Uri = "HTTPS://example.com/".parse().unwrap();
        assert_eq!(http_scheme_is_tls(uri.scheme_str()), Ok(true));
        let uri: Uri = "ftp://example.com/".parse().unwrap();
        assert_eq!(
            http_scheme_is_tls(uri.scheme_str()),
            Err(HttpError::UnsupportedScheme)
        );
    }

    #[test]
    fn ephemeral_cursor_wraps_within_range() {
        let cursor = AtomicU16::new(EPHEMERAL_LAST - 1);
        assert_eq!(next_ephemeral_port(&cursor), EPHEMERAL_LAST - 1);
        assert_eq!(next_ephemeral_port(&cursor), EPHEMERAL_LAST);
        assert_eq!(next_ephemeral_port(&cursor), EPHEMERAL_FIRST);
        assert_eq!(next_ephemeral_port(&cursor), EPHEMERAL_FIRST + 1);
        // An out-of-range cursor (e.g. a stale seed) restarts at the base.
        let cursor = AtomicU16::new(100);
        assert_eq!(next_ephemeral_port(&cursor), EPHEMERAL_FIRST);
        assert_eq!(next_ephemeral_port(&cursor), EPHEMERAL_FIRST + 1);
        let cursor = AtomicU16::new(0);
        assert_eq!(next_ephemeral_port(&cursor), EPHEMERAL_FIRST);
    }

    #[test]
    fn ephemeral_cursor_is_unique_across_threads_through_the_wrap() {
        const RANGE: usize = (EPHEMERAL_LAST - EPHEMERAL_FIRST) as usize + 1;
        const THREADS: usize = 8;
        let cursor = Arc::new(AtomicU16::new(EPHEMERAL_LAST - 100));
        // Exactly one full pass over the range, split across threads: every
        // port must be handed out exactly once.
        let per = RANGE / THREADS;
        assert_eq!(per * THREADS, RANGE);
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let cursor = cursor.clone();
                std::thread::spawn(move || {
                    (0..per)
                        .map(|_| next_ephemeral_port(&cursor))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut seen = vec![false; 65536];
        for h in handles {
            for p in h.join().unwrap() {
                assert!((EPHEMERAL_FIRST..=EPHEMERAL_LAST).contains(&p));
                assert!(!seen[p as usize], "port {p} handed out twice");
                seen[p as usize] = true;
            }
        }
    }

    #[test]
    fn canonical_hosts_are_borrowed_and_mixed_case_is_normalized() {
        let host = "example.com";
        let normalized = normalized_host(host);
        assert!(matches!(normalized, Cow::Borrowed(_)));
        assert_eq!(normalized.as_ptr(), host.as_ptr());
        assert_eq!(normalized_host("ExAmPlE.COM"), "example.com");
        assert_eq!(normalized_host("127.0.0.1"), "127.0.0.1");
    }
}
