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
    /// Header fields not listed are kept unchanged (§5.1).
    pub headers: Vec<HeaderRecipe>,
    /// Body recipe (JSON key `b`) (§5.2).
    pub body: BodyRecipe,
}

/// Recipe that recreates the previous instances of one header field name
/// (§5.1).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HeaderRecipe {
    /// Header field name, compared case-insensitively.
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
/// instance of the name in the header block.
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
    /// `d`: emit these literal body lines or header field values.
    Data(Vec<String>),
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
    /// [`BodyRecipe::None`] when both bodies are identical.
    pub fn diff(
        original: &AuthenticatedMessage<'_>,
        modified: &AuthenticatedMessage<'_>,
    ) -> Recipe {
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

                let steps = diff_steps(&values.original, &values.modified);
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
        } else {
            let orig_lines = body_lines(orig_body);
            let mod_lines = body_lines(mod_body);
            BodyRecipe::Steps(diff_steps(&orig_lines, &mod_lines))
        };

        Recipe { headers, body }
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
    /// Returns [`Dkim2Error::Modified`] if the body recipe is
    /// [`BodyRecipe::Unreconstructable`].
    pub fn apply(&self, headers: &[(&[u8], &[u8])], body: &[u8]) -> crate::Result<Vec<u8>> {
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

        let mut out = Vec::new();
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

        match &self.body {
            BodyRecipe::None => {
                out.extend_from_slice(body);
            }
            BodyRecipe::Unreconstructable => {
                return Err(crate::Error::Dkim2(Dkim2Error::Modified));
            }
            BodyRecipe::Steps(steps) => {
                let lines = body_lines(body);
                apply_body_recipe(&lines, steps, &mut out);
            }
        }

        Ok(out)
    }

    /// Appends the JSON encoding of this recipe (§5) to `out`.
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2Error::RecipeSyntax`] if serialization fails.
    pub fn to_json(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        serde_json::to_writer(out, self).map_err(|_| crate::Error::Dkim2(Dkim2Error::RecipeSyntax))
    }

    /// Parses a recipe from its JSON encoding (§5). Unknown keys, and steps
    /// that are not a `c` or `d` object, are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`Dkim2Error::RecipeSyntax`] if `bytes` is not a JSON object
    /// or does not match the recipe structure.
    pub fn from_json(bytes: &[u8]) -> crate::Result<Recipe> {
        serde_json::from_slice(bytes).map_err(|_| crate::Error::Dkim2(Dkim2Error::RecipeSyntax))
    }
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

    for step in steps {
        match step {
            Step::Copy { start, end } => {
                let high = (*end).min(instances.len() as u32);
                for i in *start..=high {
                    if let Some(line) = instances
                        .len()
                        .checked_sub(i as usize)
                        .and_then(|idx| instances.get(idx))
                    {
                        emitted.push(*line);
                    }
                }
            }
            Step::Data(values) => {
                for value in values {
                    emitted.push(value.as_bytes());
                }
            }
        }
    }

    emitted.reverse();
    emitted
}

pub(crate) fn apply_body_recipe(lines: &[&[u8]], steps: &[Step], out: &mut Vec<u8>) {
    let mark = out.len();

    for step in steps {
        match step {
            Step::Copy { start, end } => {
                let high = (*end).min(lines.len() as u32);
                for i in *start..=high {
                    if let Some(idx) = (i as usize).checked_sub(1)
                        && let Some(line) = lines.get(idx)
                    {
                        out.extend_from_slice(line);
                        out.extend_from_slice(b"\r\n");
                    }
                }
            }
            Step::Data(values) => {
                for value in values {
                    out.extend_from_slice(value.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
        }
    }

    if out.len() == mark {
        out.extend_from_slice(b"\r\n");
    }
}

fn diff_steps(original: &[&[u8]], modified: &[&[u8]]) -> Vec<Step> {
    let mut steps: Vec<Step> = Vec::new();
    let mut data: Vec<String> = Vec::new();

    for op in capture_diff_slices(Algorithm::Myers, modified, original) {
        match op {
            DiffOp::Equal { old_index, len, .. } => {
                if !data.is_empty() {
                    steps.push(Step::Data(std::mem::take(&mut data)));
                }
                steps.push(Step::Copy {
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
                for line in &original[new_index..new_index + new_len] {
                    data.push(unfold_lossy(line));
                }
            }
            DiffOp::Delete { .. } => {}
        }
    }
    if !data.is_empty() {
        steps.push(Step::Data(data));
    }
    steps
}

pub(crate) fn unfold_lossy(value: &[u8]) -> String {
    if memchr::memchr2(b'\r', b'\n', value).is_none() {
        return lossy_string(value.to_vec());
    }

    let mut result = Vec::with_capacity(value.len());
    let mut last_is_crlf = false;
    let mut rest = value;

    loop {
        let split_at = memchr::memchr2(b'\r', b'\n', rest).unwrap_or(rest.len());
        let (run, tail) = rest.split_at(split_at);
        if let Some((&first, others)) = run.split_first() {
            if last_is_crlf && !first.is_ascii_whitespace() && !result.is_empty() {
                result.push(b' ');
            }
            result.push(first);
            result.extend_from_slice(others);
        }
        match tail.split_first() {
            Some((_, next)) => {
                last_is_crlf = true;
                rest = next;
            }
            None => break,
        }
    }

    lossy_string(result)
}

fn lossy_string(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
}

#[cfg(test)]
mod tests;
