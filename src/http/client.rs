use bytes::Bytes;
use http::{Request, Response};

use super::errors::HttpError;

pub trait HttpClient {
    fn request(
        &self,
        request: Request<Bytes>,
    ) -> impl Future<Output = Result<Response<Bytes>, HttpError>> + Send;
}
