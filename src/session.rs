use std::collections::HashSet;

use crate::message::WireQuery;
use crate::utils::decode_dns;
use crate::{Error, MAX_DNS_BYTES, Query, Response, Status};

#[derive(Debug)]
#[allow(clippy::exhaustive_enums)]
pub enum Incoming {
    Query(Query),
    Reply(Response),
}

#[derive(Debug)]
pub struct Server {
    pending: HashSet<u32>,
    max_pending: usize,
    max_dns_bytes: usize,
}

impl Server {
    pub fn new(max_pending: usize, max_dns_bytes: usize) -> Result<Self, Error> {
        if !(12..=MAX_DNS_BYTES).contains(&max_dns_bytes) {
            return Err(Error::InvalidLimit);
        }
        Ok(Self {
            pending: HashSet::new(),
            max_pending,
            max_dns_bytes,
        })
    }

    pub fn receive(&mut self, text: &str) -> Result<Incoming, Error> {
        let wire = serde_json::from_str::<WireQuery>(text).map_err(|_| Error::InvalidMessage)?;
        if self.pending.contains(&wire.id) {
            return Err(Error::DuplicateId);
        }
        let Ok(dns) = decode_dns(&wire.dns, self.max_dns_bytes, false) else {
            return Ok(Incoming::Reply(Response::Failure {
                id: wire.id,
                status: Status::InvalidQuery,
            }));
        };
        if self.pending.len() >= self.max_pending {
            return Ok(Incoming::Reply(Response::Failure {
                id: wire.id,
                status: Status::Overloaded,
            }));
        }
        self.pending.insert(wire.id);
        Ok(Incoming::Query(Query { id: wire.id, dns }))
    }

    pub fn finish(&mut self, response: &Response) -> Result<String, Error> {
        if !self.pending.contains(&response.id()) {
            return Err(Error::UnknownId);
        }
        let text = response.to_text()?;
        self.pending.remove(&response.id());
        Ok(text)
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}

#[derive(Debug)]
pub struct Client {
    pending: HashSet<u32>,
    max_pending: usize,
}

impl Client {
    pub fn new(max_pending: usize) -> Self {
        Self {
            pending: HashSet::new(),
            max_pending,
        }
    }

    pub fn send(&mut self, query: &Query) -> Result<String, Error> {
        if self.pending.contains(&query.id) {
            return Err(Error::DuplicateId);
        }
        if self.pending.len() >= self.max_pending {
            return Err(Error::Capacity);
        }
        let text = query.to_text()?;
        self.pending.insert(query.id);
        Ok(text)
    }

    pub fn receive(&mut self, text: &str) -> Result<Response, Error> {
        let response = Response::from_text(text)?;
        if !self.pending.remove(&response.id()) {
            return Err(Error::UnknownId);
        }
        Ok(response)
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }
}
