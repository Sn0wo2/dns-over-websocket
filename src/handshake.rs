use subtle::Choice;

use crate::utils::constant_time_eq_unique;
use crate::{PATH, SUBPROTOCOL};

#[derive(Clone, Default)]
#[allow(clippy::exhaustive_structs)]
pub struct Auth {
    pub path: Option<String>,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
}

#[allow(clippy::exhaustive_structs)]
pub struct Request<'a> {
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a [(&'a str, &'a str)],
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Auth").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_enums)]
pub enum ServerHandshakeError {
    NotFound,
    Forbidden,
    UnsupportedProtocol,
}

impl ServerHandshakeError {
    pub const fn status_code(self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::Forbidden => 403,
            Self::UnsupportedProtocol => 400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::exhaustive_enums)]
pub enum ClientHandshakeError {
    MissingProtocol,
    InvalidProtocol,
}

pub fn validate_server_request(
    auth: &Auth,
    request: &Request<'_>,
) -> Result<(), ServerHandshakeError> {
    if request.path != auth.path.as_deref().unwrap_or(PATH) {
        return Err(ServerHandshakeError::NotFound);
    }

    let mut matched = Choice::from(1);

    if !auth.query.is_empty() {
        let query = request
            .query
            .into_iter()
            .flat_map(|query| form_urlencoded::parse(query.as_bytes()))
            .collect::<Vec<_>>();

        for (name, expected) in &auth.query {
            matched &= constant_time_eq_unique(
                query
                    .iter()
                    .filter(|(candidate, _)| candidate.as_ref() == name)
                    .map(|(_, value)| value.as_ref()),
                expected,
            );
        }
    }

    for (name, expected) in &auth.headers {
        matched &= constant_time_eq_unique(
            request
                .headers
                .iter()
                .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| *value),
            expected,
        );
    }

    if !bool::from(matched) {
        return Err(ServerHandshakeError::Forbidden);
    }

    if !request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("sec-websocket-protocol")
            && value
                .split(',')
                .any(|protocol| protocol.trim_matches([' ', '\t']) == SUBPROTOCOL)
    }) {
        return Err(ServerHandshakeError::UnsupportedProtocol);
    }

    Ok(())
}

pub fn validate_client_response(headers: &[(&str, &str)]) -> Result<(), ClientHandshakeError> {
    let mut protocols = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-protocol"))
        .map(|(_, value)| *value);

    match (protocols.next(), protocols.next()) {
        (None, _) => Err(ClientHandshakeError::MissingProtocol),
        (Some(SUBPROTOCOL), None) => Ok(()),
        _ => Err(ClientHandshakeError::InvalidProtocol),
    }
}
