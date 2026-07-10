use http::{Request, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::errors::HttpError;

pub trait HttpClient {
    /// Sends `request`, encoding its body `B` to bytes for the request's
    /// `Content-Type` and decoding the response body into `R` from the
    /// response's `Content-Type`. `B`/`R` are any serde types, or the
    /// [`Empty`](super::codec::Empty) / [`Raw`](super::codec::Raw) markers.
    fn request<B: Serialize + Send + 'static, R: DeserializeOwned + 'static>(
        &self,
        request: Request<B>,
    ) -> impl Future<Output = Result<Response<R>, HttpError>> + Send;
}
