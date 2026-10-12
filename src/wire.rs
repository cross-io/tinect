//! Strict, bounded binary primitives used by every on-wire codec.
use thiserror::Error;

pub const MAX_BODY: usize = u16::MAX as usize;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("wire frame is truncated")]
    Truncated,
    #[error("wire frame has trailing bytes")]
    Trailing,
    #[error("wire length exceeds u16")]
    Length,
    #[error("wire string is not UTF-8")]
    Utf8,
    #[error("wire boolean is invalid")]
    Bool,
}

#[derive(Default)]
pub struct Writer(Vec<u8>);
impl Writer {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    pub fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    pub fn raw(&mut self, value: &[u8]) {
        self.bytes(value);
    }
    pub fn string(&mut self, value: &str) -> Result<(), Error> {
        self.len_bytes(value.as_bytes())
    }
    pub fn len_bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        let len = u16::try_from(value.len()).map_err(|_| Error::Length)?;
        self.u16(len);
        self.bytes(value);
        Ok(())
    }
    pub fn optional_string(&mut self, value: Option<&str>) -> Result<(), Error> {
        self.u8(value.is_some() as u8);
        if let Some(value) = value {
            self.string(value)?;
        }
        Ok(())
    }
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(len).ok_or(Error::Truncated)?;
        let out = self.bytes.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(out)
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(*self.take(1)?.first().expect("one byte"))
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Truncated)
    }
    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }
    pub fn string(&mut self) -> Result<String, Error> {
        std::str::from_utf8(self.bytes()?)
            .map(str::to_owned)
            .map_err(|_| Error::Utf8)
    }
    pub fn bool(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Bool),
        }
    }
    pub fn optional_string(&mut self) -> Result<Option<String>, Error> {
        if self.bool()? {
            Ok(Some(self.string()?))
        } else {
            Ok(None)
        }
    }
    pub fn remaining(&self) -> &[u8] {
        &self.bytes[self.offset..]
    }
    pub fn take_remaining(&mut self) -> &'a [u8] {
        let remaining = &self.bytes[self.offset..];
        self.offset = self.bytes.len();
        remaining
    }
    pub fn finish(self) -> Result<(), Error> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Trailing)
        }
    }
}

pub fn encode_message(kind: u8, body: Vec<u8>) -> Result<Vec<u8>, Error> {
    let len = u16::try_from(body.len()).map_err(|_| Error::Length)?;
    let mut out = Vec::with_capacity(3 + body.len());
    out.push(kind);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}
pub fn decode_message(bytes: &[u8]) -> Result<(u8, &[u8]), Error> {
    let mut r = Reader::new(bytes);
    let kind = r.u8()?;
    let body = r.bytes()?;
    r.finish()?;
    Ok((kind, body))
}
