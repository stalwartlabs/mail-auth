/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::dkim2::recipe::{BodyRecipe, HeaderRecipe, Recipe, Step};
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, SeqAccess, Unexpected, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::borrow::Cow;
use std::fmt;

impl Serialize for Recipe {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut len = usize::from(!self.headers.is_empty());
        if !matches!(self.body, BodyRecipe::None) {
            len += 1;
        }

        let mut map = serializer.serialize_map(Some(len))?;
        if !self.headers.is_empty() {
            map.serialize_entry("h", &HeaderMapRef(&self.headers))?;
        }
        match &self.body {
            BodyRecipe::None => {}
            BodyRecipe::Unreconstructable => map.serialize_entry("b", &())?,
            BodyRecipe::Steps(steps) => map.serialize_entry("b", &StepsRef(steps))?,
        }
        map.end()
    }
}

struct HeaderMapRef<'x>(&'x [HeaderRecipe]);

impl Serialize for HeaderMapRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for header in self.0 {
            map.serialize_entry(header.name.as_str(), &StepsRef(&header.steps))?;
        }
        map.end()
    }
}

struct StepsRef<'x>(&'x [Step]);

impl Serialize for StepsRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for step in self.0 {
            seq.serialize_element(&StepRef(step))?;
        }
        seq.end()
    }
}

struct StepRef<'x>(&'x Step);

impl Serialize for StepRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        match self.0 {
            Step::Copy { start, end } => map.serialize_entry("c", &[*start, *end])?,
            Step::Data(values) => map.serialize_entry("d", values)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Recipe {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(RecipeVisitor)
    }
}

struct RecipeVisitor;

impl<'de> Visitor<'de> for RecipeVisitor {
    type Value = Recipe;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a recipe object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Recipe, A::Error> {
        let mut headers = Vec::new();
        let mut body = BodyRecipe::None;
        while let Some(key) = map.next_key::<Cow<str>>()? {
            match key.as_ref() {
                "h" => headers = map.next_value::<HeaderMap>()?.0,
                "b" => {
                    body = match map.next_value::<Option<Steps>>()? {
                        None => BodyRecipe::Unreconstructable,
                        Some(steps) => BodyRecipe::Steps(steps.0),
                    };
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Recipe { headers, body })
    }
}

struct HeaderMap(Vec<HeaderRecipe>);

impl<'de> Deserialize<'de> for HeaderMap {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(HeaderMapVisitor)
    }
}

struct HeaderMapVisitor;

impl<'de> Visitor<'de> for HeaderMapVisitor {
    type Value = HeaderMap;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a map of header names to step arrays")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<HeaderMap, A::Error> {
        let mut headers = Vec::new();
        while let Some(name) = map.next_key::<String>()? {
            let steps = map.next_value::<Steps>()?;
            headers.push(HeaderRecipe {
                name,
                steps: steps.0,
            });
        }
        Ok(HeaderMap(headers))
    }
}

struct Steps(Vec<Step>);

impl<'de> Deserialize<'de> for Steps {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(StepsVisitor)
    }
}

struct StepsVisitor;

impl<'de> Visitor<'de> for StepsVisitor {
    type Value = Steps;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an array of recipe steps")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Steps, A::Error> {
        let mut steps = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(StepEntry(step)) = seq.next_element::<StepEntry>()? {
            if let Some(step) = step {
                steps.push(step);
            }
        }
        Ok(Steps(steps))
    }
}

struct StepEntry(Option<Step>);

impl<'de> Deserialize<'de> for StepEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StepEntryVisitor)
    }
}

struct StepEntryVisitor;

impl<'de> Visitor<'de> for StepEntryVisitor {
    type Value = StepEntry;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a recipe step")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StepEntry, A::Error> {
        let mut copy: Option<(u32, u32)> = None;
        let mut data: Option<Vec<String>> = None;
        while let Some(key) = map.next_key::<Cow<str>>()? {
            match key.as_ref() {
                "c" if copy.is_none() => {
                    if let CopyField::Range(start, end) = map.next_value::<CopyField>()? {
                        copy = Some((start, end));
                    }
                }
                "d" if data.is_none() => {
                    if let DataField::Values(values) = map.next_value::<DataField>()? {
                        data = Some(values);
                    }
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        let step = if let Some((start, end)) = copy {
            Some(Step::Copy { start, end })
        } else {
            data.map(Step::Data)
        };
        Ok(StepEntry(step))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StepEntry, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(StepEntry(None))
    }

    fn visit_bool<E>(self, _: bool) -> Result<StepEntry, E> {
        Ok(StepEntry(None))
    }

    fn visit_i64<E>(self, _: i64) -> Result<StepEntry, E> {
        Ok(StepEntry(None))
    }

    fn visit_u64<E>(self, _: u64) -> Result<StepEntry, E> {
        Ok(StepEntry(None))
    }

    fn visit_f64<E>(self, _: f64) -> Result<StepEntry, E> {
        Ok(StepEntry(None))
    }

    fn visit_str<E>(self, _: &str) -> Result<StepEntry, E> {
        Ok(StepEntry(None))
    }

    fn visit_none<E>(self) -> Result<StepEntry, E> {
        Ok(StepEntry(None))
    }

    fn visit_unit<E>(self) -> Result<StepEntry, E> {
        Ok(StepEntry(None))
    }
}

enum CopyField {
    Range(u32, u32),
    Other,
}

impl<'de> Deserialize<'de> for CopyField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CopyFieldVisitor)
    }
}

struct CopyFieldVisitor;

impl<'de> Visitor<'de> for CopyFieldVisitor {
    type Value = CopyField;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a [start, end] array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<CopyField, A::Error> {
        let start = seq
            .next_element::<CopyIndex>()?
            .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
        let end = seq
            .next_element::<CopyIndex>()?
            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(CopyField::Range(start.0, end.0))
    }

    fn visit_bool<E>(self, _: bool) -> Result<CopyField, E> {
        Ok(CopyField::Other)
    }

    fn visit_i64<E>(self, _: i64) -> Result<CopyField, E> {
        Ok(CopyField::Other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<CopyField, E> {
        Ok(CopyField::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<CopyField, E> {
        Ok(CopyField::Other)
    }

    fn visit_str<E>(self, _: &str) -> Result<CopyField, E> {
        Ok(CopyField::Other)
    }

    fn visit_none<E>(self) -> Result<CopyField, E> {
        Ok(CopyField::Other)
    }

    fn visit_unit<E>(self) -> Result<CopyField, E> {
        Ok(CopyField::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<CopyField, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(CopyField::Other)
    }
}

struct CopyIndex(u32);

impl<'de> Deserialize<'de> for CopyIndex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CopyIndexVisitor)
    }
}

struct CopyIndexVisitor;

impl Visitor<'_> for CopyIndexVisitor {
    type Value = CopyIndex;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a non-negative integer")
    }

    fn visit_u64<E>(self, value: u64) -> Result<CopyIndex, E> {
        Ok(CopyIndex(value as u32))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<CopyIndex, E> {
        if value >= 0 {
            Ok(CopyIndex(value as u32))
        } else {
            Err(E::invalid_value(Unexpected::Signed(value), &self))
        }
    }
}

enum DataField {
    Values(Vec<String>),
    Other,
}

impl<'de> Deserialize<'de> for DataField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(DataFieldVisitor)
    }
}

struct DataFieldVisitor;

impl<'de> Visitor<'de> for DataFieldVisitor {
    type Value = DataField;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an array of strings")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<DataField, A::Error> {
        let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(value) = seq.next_element::<String>()? {
            values.push(value);
        }
        Ok(DataField::Values(values))
    }

    fn visit_bool<E>(self, _: bool) -> Result<DataField, E> {
        Ok(DataField::Other)
    }

    fn visit_i64<E>(self, _: i64) -> Result<DataField, E> {
        Ok(DataField::Other)
    }

    fn visit_u64<E>(self, _: u64) -> Result<DataField, E> {
        Ok(DataField::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<DataField, E> {
        Ok(DataField::Other)
    }

    fn visit_str<E>(self, _: &str) -> Result<DataField, E> {
        Ok(DataField::Other)
    }

    fn visit_none<E>(self) -> Result<DataField, E> {
        Ok(DataField::Other)
    }

    fn visit_unit<E>(self) -> Result<DataField, E> {
        Ok(DataField::Other)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<DataField, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(DataField::Other)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn json(recipe: &Recipe) -> Vec<u8> {
        let mut out = Vec::new();
        recipe.to_json(&mut out).unwrap();
        out
    }

    fn r_headers(name: &str, steps: Vec<Step>) -> Recipe {
        Recipe {
            headers: vec![hr(name, steps)],
            body: BodyRecipe::None,
        }
    }

    fn hr(name: &str, steps: Vec<Step>) -> HeaderRecipe {
        HeaderRecipe {
            name: name.to_string(),
            steps,
        }
    }

    fn copy(start: u32, end: u32) -> Step {
        Step::Copy { start, end }
    }

    fn data(values: &[&str]) -> Step {
        Step::Data(values.iter().map(|v| v.to_string()).collect())
    }

    fn with_body(steps: Vec<Step>) -> Recipe {
        Recipe {
            headers: vec![],
            body: BodyRecipe::Steps(steps),
        }
    }

    /// Asserts `input` deserializes to exactly `expected`, and that re-encoding the
    /// canonical form and decoding it again yields the same value.
    fn check_decode(input: &[u8], expected: Recipe) {
        let label = String::from_utf8_lossy(input).into_owned();
        let recipe = Recipe::from_json(input).unwrap_or_else(|_| panic!("decode failed: {label}"));
        assert_eq!(recipe, expected, "decoding {label}");
        let reparsed = Recipe::from_json(&json(&recipe)).expect("re-decode failed");
        assert_eq!(reparsed, expected, "re-decoding canonical form of {label}");
    }

    /// Asserts `recipe` serializes to exactly `expected` bytes, and that those bytes
    /// deserialize back to the same value.
    fn check_encode(recipe: Recipe, expected: &[u8]) {
        assert_eq!(json(&recipe), expected, "encoding {recipe:?}");
        let decoded = Recipe::from_json(expected).expect("decode of encoded form failed");
        assert_eq!(
            decoded,
            recipe,
            "decoding {}",
            String::from_utf8_lossy(expected)
        );
    }

    #[test]
    fn serialize_byte_equality() {
        check_encode(
            r_headers("list-unsubscribe", vec![]),
            b"{\"h\":{\"list-unsubscribe\":[]}}",
        );
        check_encode(with_body(vec![copy(1, 1)]), b"{\"b\":[{\"c\":[1,1]}]}");
        check_encode(
            r_headers("subject", vec![data(&[" Simple test message"])]),
            b"{\"h\":{\"subject\":[{\"d\":[\" Simple test message\"]}]}}",
        );
        check_encode(
            r_headers("authentication-results", vec![copy(1, 3)]),
            b"{\"h\":{\"authentication-results\":[{\"c\":[1,3]}]}}",
        );
        check_encode(
            Recipe {
                headers: vec![],
                body: BodyRecipe::Unreconstructable,
            },
            b"{\"b\":null}",
        );
        check_encode(Recipe::default(), b"{}");
    }

    #[test]
    fn serialize_preserves_insertion_order() {
        check_encode(
            Recipe {
                headers: vec![hr("to", vec![copy(1, 1)]), hr("from", vec![copy(2, 2)])],
                body: BodyRecipe::Steps(vec![copy(1, 2)]),
            },
            b"{\"h\":{\"to\":[{\"c\":[1,1]}],\"from\":[{\"c\":[2,2]}]},\"b\":[{\"c\":[1,2]}]}",
        );
    }

    #[test]
    fn round_trips_combined_headers_and_body() {
        check_encode(
            Recipe {
                headers: vec![hr("x", vec![copy(1, 2), data(&["a", "b"])])],
                body: BodyRecipe::Steps(vec![data(&[""])]),
            },
            b"{\"h\":{\"x\":[{\"c\":[1,2]},{\"d\":[\"a\",\"b\"]}]},\"b\":[{\"d\":[\"\"]}]}",
        );
    }

    #[test]
    fn deserialize_preserves_header_name_case() {
        check_decode(
            b"{\"h\":{\"SUBject\":[{\"c\":[1,1]}]}}",
            r_headers("SUBject", vec![copy(1, 1)]),
        );
    }

    #[test]
    fn deserialize_body_absent_is_none() {
        check_decode(b"{\"h\":{\"x\":[]}}", r_headers("x", vec![]));
    }

    #[test]
    fn deserialize_body_null_is_unreconstructable() {
        check_decode(
            b"{\"b\":null}",
            Recipe {
                headers: vec![],
                body: BodyRecipe::Unreconstructable,
            },
        );
    }

    #[test]
    fn deserialize_rejects_null_header_value() {
        assert!(Recipe::from_json(b"{\"h\":null}").is_err());
        assert!(Recipe::from_json(b"{\"h\":{\"subject\":null}}").is_err());
    }

    #[test]
    fn deserialize_rejects_non_object_top_level() {
        assert!(Recipe::from_json(b"[]").is_err());
        assert!(Recipe::from_json(b"null").is_err());
        assert!(Recipe::from_json(b"\"x\"").is_err());
        assert!(Recipe::from_json(b"42").is_err());
    }

    #[test]
    fn deserialize_rejects_non_array_steps() {
        assert!(Recipe::from_json(b"{\"b\":5}").is_err());
        assert!(Recipe::from_json(b"{\"b\":\"x\"}").is_err());
        assert!(Recipe::from_json(b"{\"h\":{\"x\":5}}").is_err());
    }

    #[test]
    fn deserialize_ignores_unknown_top_level_keys() {
        check_decode(
            b"{\"z\":123,\"b\":[{\"c\":[1,1]}]}",
            with_body(vec![copy(1, 1)]),
        );
    }

    #[test]
    fn deserialize_ignores_unknown_step_objects() {
        check_decode(
            b"{\"b\":[{\"c\":[1,2]},{\"z\":true}]}",
            with_body(vec![copy(1, 2)]),
        );
    }

    #[test]
    fn deserialize_skips_non_object_step_elements() {
        check_decode(
            b"{\"b\":[1,\"x\",[9],null,{\"c\":[3,4]}]}",
            with_body(vec![copy(3, 4)]),
        );
    }

    #[test]
    fn deserialize_copy_precedence_over_data() {
        check_decode(
            b"{\"b\":[{\"d\":[\"x\"],\"c\":[1,2]}]}",
            with_body(vec![copy(1, 2)]),
        );
    }

    #[test]
    fn deserialize_non_array_copy_falls_through_to_data() {
        check_decode(
            b"{\"b\":[{\"c\":5,\"d\":[\"x\"]}]}",
            with_body(vec![data(&["x"])]),
        );
    }

    #[test]
    fn deserialize_extra_ignored_step_keys() {
        check_decode(
            b"{\"b\":[{\"c\":[1,2],\"x\":7,\"y\":[1,2,3]}]}",
            with_body(vec![copy(1, 2)]),
        );
    }

    #[test]
    fn deserialize_copy_extra_elements_ignored() {
        check_decode(b"{\"b\":[{\"c\":[1,2,3,4]}]}", with_body(vec![copy(1, 2)]));
    }

    #[test]
    fn deserialize_rejects_short_copy_array() {
        assert!(Recipe::from_json(b"{\"b\":[{\"c\":[1]}]}").is_err());
        assert!(Recipe::from_json(b"{\"b\":[{\"c\":[]}]}").is_err());
    }

    #[test]
    fn deserialize_rejects_non_integer_copy() {
        assert!(Recipe::from_json(b"{\"b\":[{\"c\":[1.5,2]}]}").is_err());
        assert!(Recipe::from_json(b"{\"b\":[{\"c\":[-1,2]}]}").is_err());
        assert!(Recipe::from_json(b"{\"b\":[{\"c\":[\"1\",\"2\"]}]}").is_err());
    }

    #[test]
    fn deserialize_rejects_non_string_data() {
        assert!(Recipe::from_json(b"{\"b\":[{\"d\":[1]}]}").is_err());
        assert!(Recipe::from_json(b"{\"b\":[{\"d\":[null]}]}").is_err());
    }

    #[test]
    fn deserialize_max_copy_index() {
        check_decode(
            b"{\"b\":[{\"c\":[4294967295,4294967295]}]}",
            with_body(vec![copy(u32::MAX, u32::MAX)]),
        );
    }

    #[test]
    fn deserialize_empty_data_array() {
        check_decode(b"{\"b\":[{\"d\":[]}]}", with_body(vec![data(&[])]));
    }

    #[test]
    fn deserialize_escaped_keys() {
        check_decode(
            b"{\"\\u0062\":[{\"\\u0063\":[1,2]}]}",
            with_body(vec![copy(1, 2)]),
        );
    }

    #[test]
    fn non_ascii_round_trips() {
        check_encode(
            r_headers("subject", vec![data(&["café \u{1}"])]),
            "{\"h\":{\"subject\":[{\"d\":[\"café \\u0001\"]}]}}".as_bytes(),
        );
    }

    #[test]
    fn deserialize_rejects_trailing_garbage() {
        assert!(Recipe::from_json(b"{\"b\":null} trailing").is_err());
        assert!(Recipe::from_json(b"{}{}").is_err());
    }
}
