use subtle::{Choice, ConstantTimeEq};

use crate::{PATH as DEFAULT_PATH, SUBPROTOCOL};

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
    if request.path != auth.path.as_deref().unwrap_or(DEFAULT_PATH) {
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
            let mut count = 0_usize;
            let mut value = "";
            for (candidate_name, candidate_value) in &query {
                if candidate_name.as_ref() == name.as_str() {
                    if count == 0 {
                        value = candidate_value.as_ref();
                    }
                    count = count.saturating_add(1);
                }
            }
            matched &= value.as_bytes().ct_eq(expected.as_bytes());
            matched &= Choice::from(u8::from(count == 1));
        }
    }

    for (name, expected) in &auth.headers {
        let mut count = 0_usize;
        let mut value = "";
        for (candidate_name, candidate_value) in request.headers {
            if candidate_name.eq_ignore_ascii_case(name) {
                if count == 0 {
                    value = *candidate_value;
                }
                count = count.saturating_add(1);
            }
        }
        matched &= value.as_bytes().ct_eq(expected.as_bytes());
        matched &= Choice::from(u8::from(count == 1));
    }

    if !bool::from(matched) {
        return Err(ServerHandshakeError::Forbidden);
    }

    if !request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("sec-websocket-protocol")
            && value.split(',').any(|protocol| {
                protocol.trim_matches(|character| character == ' ' || character == '\t')
                    == SUBPROTOCOL
            })
    }) {
        return Err(ServerHandshakeError::UnsupportedProtocol);
    }

    Ok(())
}

pub fn validate_client_response(headers: &[(&str, &str)]) -> Result<(), ClientHandshakeError> {
    let mut selected = None;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("sec-websocket-protocol") {
            if selected.is_some() {
                return Err(ClientHandshakeError::InvalidProtocol);
            }
            selected = Some(*value);
        }
    }

    match selected {
        None => Err(ClientHandshakeError::MissingProtocol),
        Some(SUBPROTOCOL) => Ok(()),
        Some(_) => Err(ClientHandshakeError::InvalidProtocol),
    }
}
