//! Strict typed access to members of untrusted JSON objects. Unknown members are ignored
//! (WebIDL dictionaries ignore them); known members must have the right type and size.
//! `null` is not accepted in place of an absent member.

use crate::error::Error;
use hirz_proto::base64url;
use hirz_proto::json::Json;

pub(crate) type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct Obj<'a>(&'a Json);

impl<'a> Obj<'a> {
    pub(crate) fn new(v: &'a Json, what: &'static str) -> Result<Obj<'a>> {
        match v {
            Json::Object(_) => Ok(Obj(v)),
            _ => Err(Error::InvalidOptions(what)),
        }
    }

    pub(crate) fn get(&self, key: &str) -> Option<&'a Json> {
        self.0.get(key)
    }

    pub(crate) fn members(&self) -> &'a [(String, Json)] {
        self.0.as_object().unwrap_or(&[])
    }

    pub(crate) fn opt_obj(&self, key: &'static str) -> Result<Option<Obj<'a>>> {
        self.get(key).map(|v| Obj::new(v, key)).transpose()
    }

    pub(crate) fn req_obj(&self, key: &'static str) -> Result<Obj<'a>> {
        self.opt_obj(key)?.ok_or(Error::InvalidOptions(key))
    }

    pub(crate) fn opt_str(&self, key: &'static str, max_chars: usize) -> Result<Option<&'a str>> {
        self.get(key)
            .map(|v| text(v, max_chars).ok_or(Error::InvalidOptions(key)))
            .transpose()
    }

    pub(crate) fn req_str(&self, key: &'static str, max_chars: usize) -> Result<&'a str> {
        self.opt_str(key, max_chars)?
            .ok_or(Error::InvalidOptions(key))
    }

    pub(crate) fn opt_bool(&self, key: &'static str) -> Result<Option<bool>> {
        self.get(key)
            .map(|v| v.as_bool().ok_or(Error::InvalidOptions(key)))
            .transpose()
    }

    /// An optional number; only its type is checked.
    pub(crate) fn opt_number(&self, key: &'static str) -> Result<()> {
        match self.get(key) {
            None | Some(Json::Number(_)) => Ok(()),
            Some(_) => Err(Error::InvalidOptions(key)),
        }
    }

    pub(crate) fn opt_array(&self, key: &'static str, max_items: usize) -> Result<&'a [Json]> {
        match self.get(key) {
            None => Ok(&[]),
            Some(v) => {
                let items = v.as_array().ok_or(Error::InvalidOptions(key))?;
                if items.len() > max_items {
                    return Err(Error::InvalidOptions(key));
                }
                Ok(items)
            }
        }
    }

    pub(crate) fn req_array(&self, key: &'static str, max_items: usize) -> Result<&'a [Json]> {
        if self.get(key).is_none() {
            return Err(Error::InvalidOptions(key));
        }
        self.opt_array(key, max_items)
    }

    pub(crate) fn opt_bytes(
        &self,
        key: &'static str,
        min: usize,
        max: usize,
    ) -> Result<Option<Vec<u8>>> {
        self.get(key)
            .map(|v| {
                v.as_str()
                    .and_then(|s| b64(s, min, max))
                    .ok_or(Error::InvalidOptions(key))
            })
            .transpose()
    }

    pub(crate) fn req_bytes(&self, key: &'static str, min: usize, max: usize) -> Result<Vec<u8>> {
        self.opt_bytes(key, min, max)?
            .ok_or(Error::InvalidOptions(key))
    }

    /// An optional list of strings, each at most `max_chars` characters.
    pub(crate) fn opt_str_list(
        &self,
        key: &'static str,
        max_items: usize,
        max_chars: usize,
    ) -> Result<Vec<&'a str>> {
        self.opt_array(key, max_items)?
            .iter()
            .map(|v| text(v, max_chars).ok_or(Error::InvalidOptions(key)))
            .collect()
    }
}

/// A string of at most `max_chars` Unicode scalar values.
pub(crate) fn text(v: &Json, max_chars: usize) -> Option<&str> {
    let s = v.as_str()?;
    // Cheap byte bound first so a huge string is not walked.
    if s.len() > max_chars.saturating_mul(4) || s.chars().count() > max_chars {
        return None;
    }
    Some(s)
}

/// Unpadded base64url decoding to `min..=max` bytes, with the encoded length bounded
/// before decoding.
pub(crate) fn b64(s: &str, min: usize, max: usize) -> Option<Vec<u8>> {
    let max_encoded = max.div_ceil(3).saturating_mul(4);
    if s.len() > max_encoded {
        return None;
    }
    let out = base64url::decode(s).ok()?;
    (min..=max).contains(&out.len()).then_some(out)
}
