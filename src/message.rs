use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::MAX_DNS_BYTES;
use crate::utils::{decode_dns, validate_dns};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[allow(clippy::exhaustive_enums)]
pub enum Error {
    #[error("invalid protocol message")]
    InvalidMessage,
    #[error("invalid DNS message")]
    InvalidDns,
    #[error("request ID is already pending")]
    DuplicateId,
    #[error("request ID is not pending")]
    UnknownId,
    #[error("pending request limit reached")]
    Capacity,
    #[error("invalid DNS message size limit")]
    InvalidLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::exhaustive_enums)]
pub enum Status {
    InvalidQuery,
    UpstreamFailure,
    Timeout,
    Overloaded,
    InternalError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_structs)]
pub struct Query {
    pub id: u32,
    pub dns: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct WireQuery {
    pub id: u32,
    pub dns: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_enums)]
pub enum Response {
    Success { id: u32, dns: Vec<u8> },
    Failure { id: u32, status: Status },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", deny_unknown_fields)]
enum WireResponse {
    #[serde(rename = "SUCCESS")]
    Success { id: u32, dns: String },
    #[serde(rename = "INVALID_QUERY")]
    InvalidQuery { id: u32 },
    #[serde(rename = "UPSTREAM_FAILURE")]
    UpstreamFailure { id: u32 },
    #[serde(rename = "TIMEOUT")]
    Timeout { id: u32 },
    #[serde(rename = "OVERLOADED")]
    Overloaded { id: u32 },
    #[serde(rename = "INTERNAL_ERROR")]
    InternalError { id: u32 },
}

impl Query {
    pub fn from_text(text: &str) -> Result<Self, Error> {
        let wire = serde_json::from_str::<WireQuery>(text).map_err(|_| Error::InvalidMessage)?;
        Ok(Self {
            id: wire.id,
            dns: decode_dns(&wire.dns, MAX_DNS_BYTES, false)?,
        })
    }

    pub fn to_text(&self) -> Result<String, Error> {
        validate_dns(&self.dns, false)?;
        serde_json::to_string(&WireQuery {
            id: self.id,
            dns: URL_SAFE_NO_PAD.encode(&self.dns),
        })
        .map_err(|_| Error::InvalidMessage)
    }

    pub async fn resolve<F, Fut>(self, exchange: F) -> Response
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: Future<Output = Result<Vec<u8>, Status>>,
    {
        match exchange(self.dns).await {
            Ok(dns) if validate_dns(&dns, true).is_ok() => Response::Success { id: self.id, dns },
            Ok(_) => Response::Failure {
                id: self.id,
                status: Status::UpstreamFailure,
            },
            Err(status) => Response::Failure {
                id: self.id,
                status,
            },
        }
    }
}

impl Response {
    pub const fn id(&self) -> u32 {
        match self {
            Self::Success { id, .. } | Self::Failure { id, .. } => *id,
        }
    }

    pub fn from_text(text: &str) -> Result<Self, Error> {
        match serde_json::from_str(text).map_err(|_| Error::InvalidMessage)? {
            WireResponse::Success { id, dns } => Ok(Self::Success {
                id,
                dns: decode_dns(&dns, MAX_DNS_BYTES, true)?,
            }),
            WireResponse::InvalidQuery { id } => Ok(Self::Failure {
                id,
                status: Status::InvalidQuery,
            }),
            WireResponse::UpstreamFailure { id } => Ok(Self::Failure {
                id,
                status: Status::UpstreamFailure,
            }),
            WireResponse::Timeout { id } => Ok(Self::Failure {
                id,
                status: Status::Timeout,
            }),
            WireResponse::Overloaded { id } => Ok(Self::Failure {
                id,
                status: Status::Overloaded,
            }),
            WireResponse::InternalError { id } => Ok(Self::Failure {
                id,
                status: Status::InternalError,
            }),
        }
    }

    pub fn to_text(&self) -> Result<String, Error> {
        serde_json::to_string(&match self {
            Self::Success { id, dns } => {
                validate_dns(dns, true)?;
                WireResponse::Success {
                    id: *id,
                    dns: URL_SAFE_NO_PAD.encode(dns),
                }
            }
            Self::Failure { id, status } => match status {
                Status::InvalidQuery => WireResponse::InvalidQuery { id: *id },
                Status::UpstreamFailure => WireResponse::UpstreamFailure { id: *id },
                Status::Timeout => WireResponse::Timeout { id: *id },
                Status::Overloaded => WireResponse::Overloaded { id: *id },
                Status::InternalError => WireResponse::InternalError { id: *id },
            },
        })
        .map_err(|_| Error::InvalidMessage)
    }
}
