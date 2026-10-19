/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Recipes that recreate the previous revision of a modified message (§5).
//!
//! A Reviser that changes a message records a [`Recipe`] in the `r=` tag of
//! the new `Message-Instance`. The verifier applies it to recreate the
//! previous revision and check its hashes.

use crate::AuthenticatedMessage;
use crate::dkim2::Dkim2Error;
use crate::dkim2::canonicalize::{cmp_ignore_ascii_case, is_non_signed_header};
use similar::{Algorithm, DiffOp, capture_diff_slices};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeMap;

mod serde;

/// The recipes of a `Message-Instance` `r=` tag (§5).
///
/// Parsed from the `r=` tag by [`MessageInstance::parse`](super::MessageInstance::parse),
/// computed by [`Recipe::diff`] or built by the caller for
/// [`Dkim2Signer::sign_with_recipe`](super::Dkim2Signer::sign_with_recipe).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Recipe {
    /// Header recipes (JSON key `h`), one per changed header field name.
    /// Header fields not listed are kept unchanged (§5.1). Names are unique;
    /// recipes for header fields excluded from signing (§4) are dropped when
    /// parsed and refused when signing.
    pub headers: Vec<HeaderRecipe>,
    /// Body recipe (JSON key `b`) (§5.2).
    pub body: BodyRecipe,
}

/// Recipe that recreates the previous instances of one header field name
/// (§5.1).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HeaderRecipe {
    /// Header field name, compared case-insensitively and serialized in
    /// lowercase.
    pub name: String,
    /// Steps that emit the previous instances. Empty means that all
    /// instances of this header field are removed.
    pub steps: Vec<Step>,
}

/// Recipe that recreates the previous body (§5.2).
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub enum BodyRecipe {
    /// The body was not changed (no `b` key).
    #[default]
    None,
    /// Steps that emit the previous body lines.
    Steps(Vec<Step>),
    /// The previous body cannot be recreated (`b` is `null`).
    Unreconstructable,
}

/// One recipe step (§5.1 and §5.2).
///
/// Body lines are numbered top down, starting at 1 for the first body line.
/// Header field instances are numbered bottom up, starting at 1 for the last
/// instance of the name in the header block. A Signer's copy ranges start
/// at 1 or more, end at or after their start and start after the end of
/// every preceding copy step; when applied, other ranges are clamped so that
/// no line or instance is copied twice. Data lines must not contain CR or
/// LF.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Step {
    /// `c`: emit the current lines or header instances numbered `start` to
    /// `end`, inclusive.
    Copy {
        /// First line or instance number (1-based).
        start: u32,
        /// Last line or instance number (1-based, inclusive).
        end: u32,
    },
    /// `d`: emit these literal body lines or header field values (UTF-8).
    Data(Vec<String>),
    /// `u`: emit these literal body lines or header field values, for data
    /// that is not valid UTF-8. Serialized as base64.
    Bytes(Vec<Vec<u8>>),
}

struct LowerHeader<'x>(&'x [u8]);

impl<'x> LowerHeader<'x> {
    fn new(header: &'x [u8]) -> Self {
        LowerHeader(header.trim_ascii())
    }
}

impl PartialEq for LowerHeader<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Ord for LowerHeader<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_ignore_ascii_case(self.0, other.0)
    }
}

impl PartialOrd for LowerHeader<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for LowerHeader<'_> {}

impl std::hash::Hash for LowerHeader<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        for byte in self.0 {
            state.write_u8(byte.to_ascii_lowercase());
        }
    }
}

#[derive(Default)]
struct HeaderDiff<'x> {
    original: Vec<&'x [u8]>,
    modified: Vec<&'x [u8]>,
}

#[derive(Default)]
struct HeaderApply<'x> {
    current: Vec<&'x [u8]>,
    recipe: Option<&'x HeaderRecipe>,
}

impl Recipe {
    /// Computes the recipe that recreates `original` from `modified`.
    ///
    /// Header fields excluded from DKIM2 hashing (§4) are ignored. Header
    /// field names in the result are lowercase. The body recipe is
    /// [`BodyRecipe::None`] when both bodies are identical, and
    /// [`BodyRecipe::Unreconstructable`] when the bodies differ and the
    /// original body has a bare CR or LF, which a recipe cannot recreate.
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2Error::HeaderNotRepresentable`] when a header field
    /// value that the recipe must recreate has a bare CR or LF outside
    /// folding, since header recipes cannot be null.
    pub fn diff(
        original: &AuthenticatedMessage<'_>,
        modified: &AuthenticatedMessage<'_>,
    ) -> crate::Result<Recipe> {
        let mut header_diffs: BTreeMap<LowerHeader<'_>, HeaderDiff> = BTreeMap::new();

        for (name, value) in &original.headers {
            if !is_non_signed_header(name) {
                header_diffs
                    .entry(LowerHeader::new(name))
                    .or_default()
                    .original
                    .push(value.trim_ascii());
            }
        }
        for (name, value) in &modified.headers {
            if !is_non_signed_header(name) {
                header_diffs
                    .entry(LowerHeader::new(name))
                    .or_default()
                    .modified
                    .push(value.trim_ascii());
            }
        }

        let mut headers = Vec::new();
        for (header, mut values) in header_diffs {
            if values.original != values.modified {
                values.original.reverse();
                values.modified.reverse();

                let steps = diff_steps(&values.original, &values.modified, is_folded_value)?;
                headers.push(HeaderRecipe {
                    name: std::str::from_utf8(header.0)
                        .map(str::to_ascii_lowercase)
                        .unwrap_or_else(|_| String::from_utf8_lossy(header.0).to_ascii_lowercase()),
                    steps,
                });
            }
        }

        let orig_body = original.raw_body();
        let mod_body = modified.raw_body();
        let body = if orig_body == mod_body {
            BodyRecipe::None
        } else if has_bare_line_break(orig_body) {
            BodyRecipe::Unreconstructable
        } else {
            let orig_lines = body_lines(orig_body);
            let mod_lines = body_lines(mod_body);
            BodyRecipe::Steps(diff_steps(&orig_lines, &mod_lines, |_| true)?)
        };

        Ok(Recipe { headers, body })
    }

    /// Applies this recipe to the current header fields and body, returning
    /// the previous revision as a raw message.
    ///
    /// Header fields excluded from DKIM2 hashing (§4) are dropped, and the
    /// remaining ones are grouped by name. The output is therefore suitable
    /// for hashing, not a faithful copy of the original message.
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2Error::BodyUnreconstructable`] if the body recipe is
    /// [`BodyRecipe::Unreconstructable`].
    pub fn apply(&self, headers: &[(&[u8], &[u8])], body: &[u8]) -> crate::Result<Vec<u8>> {
        if matches!(self.body, BodyRecipe::Unreconstructable) {
            return Err(crate::Error::Dkim2(Dkim2Error::BodyUnreconstructable));
        }
        let mut out = Vec::with_capacity(headers_len(headers) + body.len());
        self.apply_headers(headers, &mut out);
        if let BodyRecipe::Steps(steps) = &self.body {
            apply_body_recipe(&body_lines(body), steps, &mut out);
        } else {
            out.extend_from_slice(body);
        }
        Ok(out)
    }

    pub(crate) fn apply_headers(&self, headers: &[(&[u8], &[u8])], out: &mut Vec<u8>) {
        let mut header_apply: BTreeMap<LowerHeader<'_>, HeaderApply> = BTreeMap::new();

        for (name, value) in headers {
            if !is_non_signed_header(name) {
                header_apply
                    .entry(LowerHeader::new(name))
                    .or_default()
                    .current
                    .push(value.trim_ascii());
            }
        }

        for recipe in &self.headers {
            header_apply
                .entry(LowerHeader::new(recipe.name.as_bytes()))
                .or_default()
                .recipe = Some(recipe);
        }

        for (name, apply) in header_apply {
            let header_values = if let Some(recipe) = apply.recipe {
                apply_header_recipe(&apply.current, &recipe.steps)
            } else {
                apply.current
            };

            for current in header_values {
                out.extend_from_slice(name.0);
                out.extend_from_slice(b": ");
                out.extend_from_slice(current);
                out.extend_from_slice(b"\r\n");
            }
        }

        out.extend_from_slice(b"\r\n");
    }

    /// Appends the JSON encoding of this recipe (§5) to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2Error::RecipeSyntax`] if the recipe fails
    /// [`validate`](Self::validate) or serialization fails.
    pub fn to_json(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        self.validate()?;
        self.write_json(out)
    }

    pub(crate) fn write_json(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        serde_json::to_writer(out, self).map_err(|_| crate::Error::Dkim2(Dkim2Error::RecipeSyntax))
    }

    /// Parses a recipe from its JSON encoding (§5).
    ///
    /// Parsing is lenient where it cannot change what the recipe
    /// reconstructs: unknown top-level keys, unknown step keys and steps that
    /// are not objects are ignored, header field names are matched without
    /// regard to case and stored in lowercase, recipes for header fields
    /// excluded from signing (§4) are dropped, empty arrays are accepted,
    /// `u` values are decoded leniently, and copy ranges are only bounded
    /// when applied. It is strict about what could make a reconstruction
    /// ambiguous or inject header fields: header field names must be RFC 5322
    /// field names and unique, data must not contain CR or LF, and a step
    /// must not hold more than one of `c`, `d` or `u`. Use
    /// [`validate`](Self::validate) for the strict rules a Signer follows.
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2Error::RecipeSyntax`] if `bytes` is not valid JSON or
    /// breaks one of the strict rules.
    pub fn from_json(bytes: &[u8]) -> crate::Result<Recipe> {
        serde_json::from_slice(bytes).map_err(|_| crate::Error::Dkim2(Dkim2Error::RecipeSyntax))
    }

    /// Checks the rules of §5 that a Signer must follow and the structure of
    /// [`Recipe`] does not enforce: at least one header or body recipe,
    /// unique header field names that are RFC 5322 field names and are
    /// signed (§4), copy ranges that start at 1 or more, end at or after
    /// their start and ascend, and non-empty data steps without CR or LF.
    /// The signers and [`to_json`](Self::to_json) apply it;
    /// [`from_json`](Self::from_json) is more lenient.
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2Error::RecipeSyntax`] when a rule is broken.
    pub fn validate(&self) -> crate::Result<()> {
        let valid = (!self.headers.is_empty() || !matches!(self.body, BodyRecipe::None))
            && self.headers.iter().all(|header| {
                is_field_name(header.name.as_bytes())
                    && !is_non_signed_header(header.name.as_bytes())
                    && valid_steps(&header.steps)
            })
            && unique_names(&self.headers, &[])
            && match &self.body {
                BodyRecipe::Steps(steps) => valid_steps(steps),
                BodyRecipe::None | BodyRecipe::Unreconstructable => true,
            };
        if valid {
            Ok(())
        } else {
            Err(crate::Error::Dkim2(Dkim2Error::RecipeSyntax))
        }
    }
}

pub(super) fn is_field_name(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|&ch| ch.is_ascii_graphic() && ch != b':')
}

pub(super) fn unique_names(headers: &[HeaderRecipe], others: &[String]) -> bool {
    let count = headers.len() + others.len();
    let names = || {
        headers
            .iter()
            .map(|header| header.name.as_bytes())
            .chain(others.iter().map(String::as_bytes))
    };
    if count <= UNIQUE_SCAN_LIMIT {
        names().enumerate().all(|(pos, name)| {
            names()
                .skip(pos + 1)
                .all(|other| !other.eq_ignore_ascii_case(name))
        })
    } else {
        let mut sorted = names().map(LowerHeader::new).collect::<Vec<_>>();
        sorted.sort_unstable();
        sorted.windows(2).all(|pair| pair.first() != pair.last())
    }
}

const UNIQUE_SCAN_LIMIT: usize = 16;

fn valid_steps(steps: &[Step]) -> bool {
    let mut last_end = 0;
    steps.iter().all(|step| match step {
        Step::Copy { start, end } => {
            let valid = *start > last_end && start <= end;
            last_end = *end;
            valid
        }
        Step::Data(values) => {
            !values.is_empty()
                && values
                    .iter()
                    .all(|value| !serde::has_line_break(value.as_bytes()))
        }
        Step::Bytes(values) => {
            !values.is_empty() && values.iter().all(|value| !serde::has_line_break(value))
        }
    })
}

pub(crate) fn headers_len(headers: &[(&[u8], &[u8])]) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.len() + value.len() + 4)
        .sum::<usize>()
        + 2
}

pub(crate) fn body_lines(body: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::with_capacity(memchr::memchr_iter(b'\n', body).count() + 1);
    let mut start = 0;

    for pos in memchr::memchr_iter(b'\n', body) {
        let line = body.get(start..pos).unwrap_or_default();
        lines.push(line.strip_suffix(b"\r").unwrap_or(line));
        start = pos + 1;
    }
    let line = body.get(start..).unwrap_or_default();
    lines.push(line.strip_suffix(b"\r").unwrap_or(line));

    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }

    lines
}

pub(crate) fn apply_header_recipe<'x>(instances: &[&'x [u8]], steps: &'x [Step]) -> Vec<&'x [u8]> {
    let mut emitted: Vec<&'x [u8]> = Vec::new();
    let mut next = 1;

    for step in steps {
        match step {
            Step::Copy { start, end } => {
                for number in copy_range(*start, *end, instances.len(), &mut next) {
                    if let Some(line) = instances
                        .len()
                        .checked_sub(number)
                        .and_then(|idx| instances.get(idx))
                    {
                        emitted.push(*line);
                    }
                }
            }
            Step::Data(values) => {
                emitted.extend(values.iter().map(String::as_bytes));
            }
            Step::Bytes(values) => {
                emitted.extend(values.iter().map(Vec::as_slice));
            }
        }
    }

    emitted.reverse();
    emitted
}

pub(crate) fn apply_body_recipe(lines: &[&[u8]], steps: &[Step], out: &mut Vec<u8>) {
    let mark = out.len();
    let mut next = 1;

    for step in steps {
        match step {
            Step::Copy { start, end } => {
                for line in copy_range(*start, *end, lines.len(), &mut next)
                    .filter_map(|number| lines.get(number - 1))
                {
                    out.extend_from_slice(line);
                    out.extend_from_slice(b"\r\n");
                }
            }
            Step::Data(values) => {
                for value in values {
                    out.extend_from_slice(value.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
            Step::Bytes(values) => {
                for value in values {
                    out.extend_from_slice(value);
                    out.extend_from_slice(b"\r\n");
                }
            }
        }
    }

    if out.len() == mark {
        out.extend_from_slice(b"\r\n");
    }
}

fn copy_range(
    start: u32,
    end: u32,
    available: usize,
    next: &mut usize,
) -> std::ops::RangeInclusive<usize> {
    let first = usize::try_from(start).unwrap_or(usize::MAX).max(*next);
    let last = usize::try_from(end).unwrap_or(usize::MAX).min(available);
    if first <= last {
        *next = last + 1;
    }
    first..=last
}

fn has_bare_line_break(value: &[u8]) -> bool {
    memchr::memchr2_iter(b'\r', b'\n', value).any(|pos| match value.get(pos) {
        Some(b'\r') => value.get(pos + 1) != Some(&b'\n'),
        _ => pos.checked_sub(1).and_then(|prev| value.get(prev)) != Some(&b'\r'),
    })
}

fn is_folded_value(value: &[u8]) -> bool {
    !has_bare_line_break(value)
        && memchr::memchr_iter(b'\n', value)
            .all(|pos| matches!(value.get(pos + 1), Some(b' ' | b'\t')))
}

fn diff_steps(
    original: &[&[u8]],
    modified: &[&[u8]],
    representable: fn(&[u8]) -> bool,
) -> crate::Result<Vec<Step>> {
    let mut steps = DataSteps::default();

    for op in capture_diff_slices(Algorithm::Myers, modified, original) {
        match op {
            DiffOp::Equal { old_index, len, .. } => {
                steps.flush();
                steps.steps.push(Step::Copy {
                    start: old_index as u32 + 1,
                    end: (old_index + len) as u32,
                });
            }
            DiffOp::Insert {
                new_index, new_len, ..
            }
            | DiffOp::Replace {
                new_index, new_len, ..
            } => {
                for line in original.iter().skip(new_index).take(new_len) {
                    if !representable(line) {
                        return Err(crate::Error::Dkim2(Dkim2Error::HeaderNotRepresentable));
                    }
                    steps.push(unfold(line));
                }
            }
            DiffOp::Delete { .. } => {}
        }
    }
    steps.flush();
    Ok(steps.steps)
}

#[derive(Default)]
struct DataSteps {
    steps: Vec<Step>,
    text: Vec<String>,
    bytes: Vec<Vec<u8>>,
}

impl DataSteps {
    fn push(&mut self, line: Cow<'_, [u8]>) {
        match String::from_utf8(line.into_owned()) {
            Ok(text) => {
                if !self.bytes.is_empty() {
                    self.steps
                        .push(Step::Bytes(std::mem::take(&mut self.bytes)));
                }
                self.text.push(text);
            }
            Err(err) => {
                if !self.text.is_empty() {
                    self.steps.push(Step::Data(std::mem::take(&mut self.text)));
                }
                self.bytes.push(err.into_bytes());
            }
        }
    }

    fn flush(&mut self) {
        if !self.text.is_empty() {
            self.steps.push(Step::Data(std::mem::take(&mut self.text)));
        }
        if !self.bytes.is_empty() {
            self.steps
                .push(Step::Bytes(std::mem::take(&mut self.bytes)));
        }
    }
}

pub(crate) fn unfold(value: &[u8]) -> Cow<'_, [u8]> {
    if memchr::memchr2(b'\r', b'\n', value).is_none() {
        return Cow::Borrowed(value);
    }

    let mut result = Vec::with_capacity(value.len());
    let mut last_is_crlf = false;

    for run in value.split(|&ch| matches!(ch, b'\r' | b'\n')) {
        if let Some((&first, others)) = run.split_first() {
            if last_is_crlf && !first.is_ascii_whitespace() && !result.is_empty() {
                result.push(b' ');
            }
            result.push(first);
            result.extend_from_slice(others);
        }
        last_is_crlf = true;
    }

    Cow::Owned(result)
}

#[cfg(test)]
mod tests;
