mod measurement;
mod quote_body;
mod report_body;

pub use self::{measurement::Measurement, quote_body::QuoteBody, report_body::ReportBody};

use std::convert::TryInto;

const MIN_QUOTE_LEN: usize = 436;

/// Quote returned by QE
#[derive(Debug)]
pub struct Quote {
    /// Body of the quote
    body: QuoteBody,
    /// Report body of the quote
    report_body: ReportBody,
    /// Encrypted EPID signature over `body` and `report_body`
    signature: Vec<u8>,
}

impl Quote {
    pub fn try_copy_from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < MIN_QUOTE_LEN {
            return None;
        }

        let sig_len = u32::from_le_bytes(bytes[432..436].try_into().ok()?) as usize;

        if bytes.len() != MIN_QUOTE_LEN + sig_len {
            return None;
        }

        let body = QuoteBody::try_copy_from(&bytes[0..48])?;
        let report_body = ReportBody::try_copy_from(&bytes[48..432])?;
        let signature = bytes[436..(436 + sig_len)].to_vec();

        Some(Self {
            body,
            report_body,
            signature,
        })
    }
}
