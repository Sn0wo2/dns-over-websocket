use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use domain::base::{Message, ParsedName};
use domain::rdata::AllRecordData;
use subtle::{Choice, ConstantTimeEq};

use crate::{Error, MAX_DNS_BYTES};

pub(crate) fn constant_time_eq_unique<'a>(
    mut values: impl Iterator<Item = &'a str>,
    expected: &str,
) -> Choice {
    let value = values.next();
    value
        .unwrap_or_default()
        .as_bytes()
        .ct_eq(expected.as_bytes())
        & Choice::from(u8::from(value.is_some() && values.next().is_none()))
}

pub fn validate_dns(bytes: &[u8], response: bool) -> Result<(), Error> {
    if !(12..=MAX_DNS_BYTES).contains(&bytes.len()) {
        return Err(Error::InvalidDns);
    }
    let message = Message::from_slice(bytes).map_err(|_| Error::InvalidDns)?;
    if message.header().qr() != response {
        return Err(Error::InvalidDns);
    }
    let mut questions = message.question();
    for question in questions.by_ref() {
        question.map_err(|_| Error::InvalidDns)?;
    }
    let mut section = questions.answer().map_err(|_| Error::InvalidDns)?;
    for index in 0..3 {
        for record in section.by_ref() {
            record
                .map_err(|_| Error::InvalidDns)?
                .to_any_record::<AllRecordData<&[u8], ParsedName<&[u8]>>>()
                .map_err(|_| Error::InvalidDns)?;
        }
        if index == 2 {
            if section.pos() != bytes.len() {
                return Err(Error::InvalidDns);
            }
        } else {
            section = section
                .next_section()
                .map_err(|_| Error::InvalidDns)?
                .ok_or(Error::InvalidDns)?;
        }
    }
    Ok(())
}

pub(crate) fn decode_dns(text: &str, limit: usize, response: bool) -> Result<Vec<u8>, Error> {
    if text.len() > limit.div_ceil(3) * 4 {
        return Err(Error::InvalidDns);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error::InvalidDns)?;
    if bytes.len() > limit {
        return Err(Error::InvalidDns);
    }
    validate_dns(&bytes, response)?;
    Ok(bytes)
}
