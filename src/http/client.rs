//! The HTTP client: HTTPS via rustls (webpki roots + custom CAs, ALPN),
//! HTTP/1.1 and HTTP/2 via hyper's low-level `client::conn` API, over
//! `TcpStream`.
//!
//! The request/response API uses the `http` crate's types directly:
//! `http::Request<Bytes>` in, `http::Response<Bytes>` out (the response
//! body is collected to completion; this client does not stream bodies).
//!
//! Connection reuse: HTTP/2 connections are pooled per origin
//! (host, port) and multiplexed -- hyper's h2 `SendRequest` is `Clone`,
//! so any number of requests share one TCP+TLS connection until the
//! server closes it (there is no idle timeout on our side). HTTP/1.1 has
//! no such multiplexing handle and stays connection-per-request.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};

use bytes::Bytes;
use http::request::Parts;
use http::{HeaderValue, Method, Request, Response, Uri, Version, header};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::TlsConnector;

use crate::core::hashmap::HashMap;
use crate::tcp::worker::WorkerHandle;

use super::stream::{FlushHandle, TcpOptions, TcpStream};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Origin key for the h2 pool: (host, port). Scheme is implicit (only
/// `https` + ALPN produces an h2 connection), and corked requests never
/// reach the pool (they force h1), so transport options aren't part of
/// the key.
type Origin = (String, u16);
type H2Pool = AsyncMutex<HashMap<Origin, http2::SendRequest<Full<Bytes>>>>;

pub mod builder {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU16;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rustls::RootCertStore;
    use tokio::sync::Mutex;
    use tokio_rustls::TlsConnector;

    use super::{Error, HttpClient};

    use crate::core::hashmap::HashMap;
    use crate::tcp::worker::WorkerHandle;

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
        pub fn add_root_ca_pem(mut self, pem: &[u8]) -> Result<Self, Error> {
            let mut reader = std::io::Cursor::new(pem);
            let mut added = 0usize;
            for cert in rustls_pemfile::certs(&mut reader) {
                self.roots.add(cert?)?;
                added += 1;
            }
            if added == 0 {
                return Err("no CA certificates found in PEM input".into());
            }
            Ok(self)
        }

        pub fn add_root_ca_pem_file(self, path: &str) -> Result<Self, Error> {
            let pem = std::fs::read(path)?;
            self.add_root_ca_pem(&pem)
        }

        /// Maps a hostname to an IPv4 address (curl `--resolve` style). The
        /// hostname is still used for SNI and certificate validation; only
        /// the TCP connection goes to `ip`.
        pub fn resolve(mut self, host: &str, ip: Ipv4Addr) -> Self {
            self.resolve.insert(host.to_ascii_lowercase(), ip);
            self
        }

        pub fn build(self, worker: WorkerHandle) -> HttpClient {
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

            HttpClient {
                worker,
                tls: TlsConnector::from(Arc::new(tls_config)),
                tls_h1: TlsConnector::from(Arc::new(tls_h1_config)),
                resolve: self.resolve,
                next_port: AtomicU16::new(next_port),
                h2_pool: Mutex::new(HashMap::default()),
            }
        }
    }
}

pub struct HttpClient {
    worker: WorkerHandle,
    /// ALPN offers h2 + http/1.1 (server chooses).
    tls: TlsConnector,
    /// ALPN offers http/1.1 only, used for corked requests (a manually
    /// held tail is incompatible with a shared multiplexed h2 connection).
    tls_h1: TlsConnector,
    resolve: HashMap<String, Ipv4Addr>,
    next_port: AtomicU16,
    h2_pool: H2Pool,
}

impl HttpClient {
    pub async fn get(&self, url: &str) -> Result<Response<Bytes>, Error> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Bytes::new())?;
        self.request(request).await
    }

    /// Sends one request. The request URI must be absolute (scheme +
    /// host) since it's also what decides where to connect. For `https`
    /// the protocol (HTTP/1.1 vs HTTP/2) follows the server's ALPN
    /// choice; plain `http` speaks HTTP/1.1.
    ///
    /// HTTP/2 connections are reused: if a live pooled connection to the
    /// origin exists, this request is multiplexed onto it instead of
    /// dialing a new one. HTTP/1.1 dials per request.
    ///
    /// The response's status/version/headers/extensions are the `http`
    /// crate's own parts, untouched; the body is fully collected.
    ///
    /// Transport tuning: insert a [`TcpOptions`] into the request's
    /// extensions to control TCP_NODELAY / corking for the connection
    /// this request uses (consumed here, not forwarded to the server).
    pub async fn request(&self, request: Request<Bytes>) -> Result<Response<Bytes>, Error> {
        let (mut parts, body) = request.into_parts();
        let tcp_options = parts.extensions.remove::<TcpOptions>().unwrap_or_default();
        let flush_handle = parts.extensions.remove::<FlushHandle>();

        if flush_handle.is_none() && tcp_options.cork {
            return Err("cannot cork a request without a FlushHandle in its extensions".into());
        }

        let scheme = parts.uri.scheme_str().unwrap_or("http").to_string();
        let host = parts
            .uri
            .host()
            .ok_or("request URI has no host (an absolute URI is required)")?
            .to_string();
        let port = parts
            .uri
            .port_u16()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });

        if scheme == "https" {
            // Corked requests can't share a multiplexed h2 connection, so
            // they always take the h1 path (h1-only ALPN, no pooling).
            if tcp_options.cork {
                let tcp = self
                    .dial(&host, port, tcp_options, flush_handle.as_ref())
                    .await?;
                let server_name = ServerName::try_from(host.clone())?;
                let mut tls = self.tls_h1.connect(server_name, tcp).await?;
                // Cork only now that the TLS handshake has completed.
                tls.get_mut().0.request_cork();
                return send_h1(tls, parts, body, &host, port, &scheme).await;
            }

            // Fast path: multiplex onto an existing h2 connection.
            if let Some(send_request) = self.pooled_h2(&host, port).await {
                return send_h2_on(send_request, parts, body).await;
            }

            let tcp = self
                .dial(&host, port, tcp_options, flush_handle.as_ref())
                .await?;
            let server_name = ServerName::try_from(host.clone())?;
            let tls = self.tls.connect(server_name, tcp).await?;
            let negotiated_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
            if negotiated_h2 {
                let send_request = handshake_h2(tls).await?;
                // Pool a clone; on a race where two tasks dialed the same
                // origin concurrently, last-in wins and the loser's
                // connection just serves its own request and then idles
                // until the server reaps it.
                self.h2_pool
                    .lock()
                    .await
                    .insert((host.to_ascii_lowercase(), port), send_request.clone());
                send_h2_on(send_request, parts, body).await
            } else {
                send_h1(tls, parts, body, &host, port, &scheme).await
            }
        } else {
            let tcp = self
                .dial(&host, port, tcp_options, flush_handle.as_ref())
                .await?;
            // Plain HTTP has no handshake, so cork right away.
            if tcp_options.cork {
                tcp.request_cork();
            }
            send_h1(tcp, parts, body, &host, port, &scheme).await
        }
    }

    /// Sends `request` over a fresh HTTP/1.1 connection with protocol-
    /// upgrade support and returns the raw response (body uncollected), so
    /// a `101 Switching Protocols` response keeps its `OnUpgrade` slot for
    /// `hyper::upgrade::on`. Used by the WebSocket client (`ws.rs`).
    ///
    /// Schemes: `ws`/`http` dial plain TCP; `wss`/`https` dial through the
    /// h1-only TLS connector (upgrades don't exist on multiplexed h2).
    /// Connections are never pooled and never corked -- a held tail would
    /// stall the interactive protocol the upgrade hands over to, so this
    /// path forces `cork: false` with `nodelay` on.
    pub(crate) async fn h1_upgrade_request(
        &self,
        request: Request<Bytes>,
    ) -> Result<Response<hyper::body::Incoming>, Error> {
        let (mut parts, body) = request.into_parts();
        // Corking is not allowed on upgrade connections; strip any
        // options a caller may have attached rather than honoring them.
        if let Some(options) = parts.extensions.remove::<TcpOptions>()
            && options.cork
        {
            return Err("corking is not allowed on upgrade (WebSocket) connections".into());
        }
        let tcp_options = TcpOptions {
            nodelay: true,
            cork: false,
        };

        let scheme = parts.uri.scheme_str().unwrap_or("ws").to_ascii_lowercase();
        let tls = matches!(scheme.as_str(), "wss" | "https");
        let host = parts
            .uri
            .host()
            .ok_or("request URI has no host (an absolute URI is required)")?
            .to_string();
        let default_port = if tls { 443 } else { 80 };
        let port = parts.uri.port_u16().unwrap_or(default_port);

        rewrite_to_origin_form(&mut parts, &host, port, default_port)?;
        let request = Request::from_parts(parts, Full::new(body));

        let tcp = self.dial(&host, port, tcp_options, None).await?;
        if tls {
            let server_name = ServerName::try_from(host.clone())?;
            let tls_stream = self.tls_h1.connect(server_name, tcp).await?;
            send_h1_upgradable(tls_stream, request).await
        } else {
            send_h1_upgradable(tcp, request).await
        }
    }

    async fn dial(
        &self,
        host: &str,
        port: u16,
        options: TcpOptions,
        flush_handle: Option<&FlushHandle>,
    ) -> Result<TcpStream, Error> {
        let ip = self.resolve_ip(host)?;
        let local_port = self.alloc_ephemeral_port();
        Ok(TcpStream::connect(
            &self.worker,
            ip.octets(),
            port,
            local_port,
            options,
            flush_handle,
        )
        .await?)
    }

    /// Checks out a clone of the pooled h2 `SendRequest` for this origin
    /// if the underlying connection is still alive and ready to accept a
    /// new stream; evicts dead entries.
    async fn pooled_h2(&self, host: &str, port: u16) -> Option<http2::SendRequest<Full<Bytes>>> {
        let key = (host.to_ascii_lowercase(), port);
        let mut pool = self.h2_pool.lock().await;
        let send_request = pool.get_mut(&key)?;
        if send_request.is_closed() || send_request.ready().await.is_err() {
            pool.remove(&key);
            return None;
        }
        Some(send_request.clone())
    }

    fn resolve_ip(&self, host: &str) -> Result<Ipv4Addr, Error> {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(ip);
        }
        self.resolve
            .get(&host.to_ascii_lowercase())
            .copied()
            .ok_or_else(|| {
                format!(
                    "cannot resolve host {host:?}: this stack has no DNS -- use an IP-literal \
                     URL or map the name with HttpClientBuilder::resolve()"
                )
                .into()
            })
    }

    /// Total TCP connections the worker has opened (for confirming h2
    /// reuse). See [`WorkerHandle::connections_opened`].
    pub fn connections_opened(&self) -> u64 {
        self.worker.connections_opened()
    }

    fn alloc_ephemeral_port(&self) -> u16 {
        loop {
            let port = self.next_port.fetch_add(1, Ordering::Relaxed);
            if (49152..=65535).contains(&port) {
                return port;
            }
            // Wrapped past 65535: reset the cursor into the ephemeral
            // range and retry.
            self.next_port.store(49152, Ordering::Relaxed);
        }
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
) -> Result<(), Error> {
    let origin_form: Uri = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .parse()?;
    parts.uri = origin_form;
    parts.version = Version::HTTP_11;
    if !parts.headers.contains_key(header::HOST) {
        let host_value = if port == default_port {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        parts
            .headers
            .insert(header::HOST, HeaderValue::try_from(host_value)?);
    }
    Ok(())
}

async fn send_h1<T>(
    io: T,
    mut parts: Parts,
    body: Bytes,
    host: &str,
    port: u16,
    scheme: &str,
) -> Result<Response<Bytes>, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut send_request, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    // The connection task owns the transport and must be polled for the
    // request/response to make progress.
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let default_port = if scheme == "https" { 443 } else { 80 };
    rewrite_to_origin_form(&mut parts, host, port, default_port)?;
    let request = Request::from_parts(parts, Full::new(body));

    let response = send_request.send_request(request).await?;
    collect_response(response).await
}

/// Like [`send_h1`] but for protocol upgrades: the connection task is
/// driven with `with_upgrades()` (so a `101 Switching Protocols` response
/// can hand the underlying connection to `hyper::upgrade::on`) and the
/// response is returned raw, body uncollected.
async fn send_h1_upgradable<T>(
    io: T,
    request: Request<Full<Bytes>>,
) -> Result<Response<hyper::body::Incoming>, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut send_request, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(send_request.send_request(request).await?)
}

/// Performs the h2 connection preface/SETTINGS exchange and spawns the
/// connection driver task. The returned `SendRequest` is the poolable,
/// clonable multiplexing handle; the connection stays alive as long as
/// the driver task runs (until GOAWAY or transport close).
async fn handshake_h2<T>(io: T) -> Result<http2::SendRequest<Full<Bytes>>, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(send_request)
}

/// Sends one request as a new stream on an (owned clone of an) h2
/// connection handle.
async fn send_h2_on(
    mut send_request: http2::SendRequest<Full<Bytes>>,
    mut parts: Parts,
    body: Bytes,
) -> Result<Response<Bytes>, Error> {
    // HTTP/2 derives :scheme/:authority/:path from the absolute URI the
    // caller already supplied; just pin the version.
    parts.version = Version::HTTP_2;
    let request = Request::from_parts(parts, Full::new(body));

    let response = send_request.send_request(request).await?;
    collect_response(response).await
}

/// Collects the streaming body and re-assembles the response around it,
/// leaving every other part (status, version, headers, extensions) as
/// hyper/`http` produced them.
async fn collect_response(
    response: Response<hyper::body::Incoming>,
) -> Result<Response<Bytes>, Error> {
    let (parts, body) = response.into_parts();
    let body = body.collect().await?.to_bytes();
    Ok(Response::from_parts(parts, body))
}
