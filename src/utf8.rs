/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{borrow::Cow, string::FromUtf8Error};

#[inline]
pub(crate) fn into_string(bytes: Vec<u8>) -> Result<String, FromUtf8Error> {
    if simdutf8::basic::from_utf8(&bytes).is_ok() {
        Ok(unsafe { String::from_utf8_unchecked(bytes) })
    } else {
        String::from_utf8(bytes)
    }
}

#[inline]
pub(crate) fn into_string_lossy(bytes: Vec<u8>) -> String {
    into_string(bytes).unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

#[inline]
pub(crate) fn to_str_lossy(bytes: &[u8]) -> Cow<'_, str> {
    match simdutf8::basic::from_utf8(bytes) {
        Ok(text) => Cow::Borrowed(text),
        Err(_) => String::from_utf8_lossy(bytes),
    }
}
