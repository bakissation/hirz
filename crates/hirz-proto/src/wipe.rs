//! Scratch space that is wiped when it goes away, so a parser that fails part way, or a parsed
//! value that is dropped, leaves no copy of the text or bytes it held in freed memory. The values
//! the parsers return (`Json`, `cbor::Value`) wipe themselves on drop in the same way.

use zeroize::Zeroize;

#[cfg(test)]
thread_local! {
    static WIPED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Bytes wiped by this thread since the last call to [`take_wiped`]; for tests.
#[cfg(test)]
pub(crate) fn take_wiped() -> usize {
    WIPED.with(|c| c.replace(0))
}

#[cfg(test)]
fn count(n: usize) {
    WIPED.with(|c| c.set(c.get().saturating_add(n)));
}

#[cfg(not(test))]
fn count(_: usize) {}

pub(crate) fn string(s: &mut String) {
    count(s.len());
    s.zeroize();
}

pub(crate) fn bytes(b: &mut Vec<u8>) {
    count(b.len());
    b.zeroize();
}

/// A string being built. Whatever is in it when this is dropped is wiped; `into_string` hands the
/// finished text on without a copy.
#[derive(Default)]
pub(crate) struct Text(String);

impl Text {
    pub(crate) fn with_capacity(n: usize) -> Text {
        Text(String::with_capacity(n))
    }

    pub(crate) fn push(&mut self, c: char) {
        self.0.push(c);
    }

    pub(crate) fn push_str(&mut self, s: &str) {
        self.0.push_str(s);
    }

    pub(crate) fn into_string(mut self) -> String {
        core::mem::take(&mut self.0)
    }
}

impl Drop for Text {
    fn drop(&mut self) {
        string(&mut self.0);
    }
}

/// Bytes being built, wiped the same way.
#[derive(Default)]
pub(crate) struct Buffer(Vec<u8>);

impl Buffer {
    pub(crate) fn with_capacity(n: usize) -> Buffer {
        Buffer(Vec::with_capacity(n))
    }

    pub(crate) fn push(&mut self, b: u8) {
        self.0.push(b);
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        bytes(&mut self.0);
    }
}
