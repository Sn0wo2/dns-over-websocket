#![allow(clippy::pub_use)]

pub mod handshake;
mod message;
mod session;
mod utils;

pub use message::{Error, Query, Response, Status};
pub use session::{Client, Incoming, Server};
pub use utils::validate_dns;

pub const PATH: &str = "/ws-dns-query";
pub const SUBPROTOCOL: &str = "v1.dns-ws";
pub const MAX_DNS_BYTES: usize = 65_535;
