/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::dmarc::Policy;
use crate::report::{
    ReportError,
    dmarc::{AggregateReport, Discovery, PolicyOverride, SpfScope},
    test_util::{gzip, message_with_attachment, zip},
};
use std::{fs, path::PathBuf};
const MAX_REPORT_SIZE: usize = 25 * 1024 * 1024;

fn resource(name: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("resources");
    path.push("dmarc-feedback");
    path.push(name);
    fs::read(path).unwrap()
}

const REPORT: &str = concat!(
    r#"<?xml version="1.0" encoding="UTF-8"?><feedback><report_metadata>"#,
    r#"<org_name>Example</org_name><email>dmarc@example.org</email>"#,
    r#"<report_id>1</report_id><date_range><begin>1</begin><end>2</end></date_range>"#,
    r#"</report_metadata><policy_published><domain>example.org</domain>"#,
    r#"</policy_published></feedback>"#
);

#[test]
fn dmarc_report_rfc9990_sample() {
    let report = AggregateReport::parse_xml(&resource("004.xml")).unwrap();
    assert_eq!(report.policy_published.domain, "example.com");
    assert_eq!(report.policy_published.np, Policy::None);
    assert_eq!(
        report.policy_published.discovery_method,
        Discovery::Treewalk
    );
    assert_eq!(
        report.report_metadata.generator.as_deref(),
        Some("Example DMARC Aggregate Reporter v1.2")
    );
    assert!(!report.policy_published.testing);

    let reparsed = AggregateReport::parse_xml(report.to_xml().as_bytes()).unwrap();
    assert_eq!(report, reparsed);
}

#[test]
fn dmarc_report_rfc7489_backwards_compat() {
    let report = AggregateReport::parse_xml(&resource("005.xml")).unwrap();
    assert_eq!(report.policy_published.domain, "example.com");
    assert_eq!(report.policy_published.p, Policy::Reject);
    assert_eq!(report.policy_published.np, Policy::Unspecified);
    assert_eq!(
        report.policy_published.discovery_method,
        Discovery::Unspecified
    );
    assert_eq!(report.report_metadata.generator, None);

    let record = &report.records[0];
    assert_eq!(
        record.row.policy_evaluated.reason[0].kind,
        PolicyOverride::Other
    );
    assert_eq!(record.auth_results.spf[0].scope, SpfScope::Helo);
}

#[test]
fn dmarc_report_parse() {
    let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("resources");
    test_dir.push("dmarc-feedback");

    for file_name in fs::read_dir(&test_dir).unwrap() {
        let mut file_name = file_name.unwrap().path();
        if !file_name.extension().unwrap().to_str().unwrap().eq("xml") {
            continue;
        }
        println!("Parsing DMARC feedback {}", file_name.to_str().unwrap());

        let feedback = AggregateReport::parse_xml(&fs::read(&file_name).unwrap()).unwrap();

        file_name.set_extension("json");

        let expected_feedback =
            serde_json::from_slice::<AggregateReport>(&fs::read(&file_name).unwrap()).unwrap();

        assert_eq!(expected_feedback, feedback);
    }
}

#[test]
fn dmarc_report_eml_parse() {
    let mut test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_dir.push("resources");
    test_dir.push("dmarc-feedback");

    for file_name in fs::read_dir(&test_dir).unwrap() {
        let mut file_name = file_name.unwrap().path();
        if !file_name.extension().unwrap().to_str().unwrap().eq("eml") {
            continue;
        }
        println!("Parsing DMARC feedback {}", file_name.to_str().unwrap());

        let feedback =
            AggregateReport::parse_rfc5322(&fs::read(&file_name).unwrap(), MAX_REPORT_SIZE)
                .unwrap();

        file_name.set_extension("json");

        let expected_feedback =
            serde_json::from_slice::<AggregateReport>(&fs::read(&file_name).unwrap()).unwrap();

        assert_eq!(expected_feedback, feedback);
    }
}

#[test]
fn dmarc_report_zip_forged_size() {
    let archive = zip("report.xml", REPORT.as_bytes(), None, Some(u32::MAX));
    let message = message_with_attachment("application/zip", "report.zip", &archive);

    assert_eq!(
        AggregateReport::parse_rfc5322(&message, MAX_REPORT_SIZE),
        Err(ReportError::TooLarge)
    );
}

#[test]
fn dmarc_report_zip_forged_compressed_size() {
    let archive = zip("report.xml", REPORT.as_bytes(), Some(u32::MAX), None);
    let message = message_with_attachment("application/zip", "report.zip", &archive);

    assert!(AggregateReport::parse_rfc5322(&message, MAX_REPORT_SIZE).is_err());
}

#[test]
fn dmarc_report_zip_within_limit() {
    let archive = zip("report.xml", REPORT.as_bytes(), None, None);
    let message = message_with_attachment("application/zip", "report.zip", &archive);

    assert_eq!(
        AggregateReport::parse_rfc5322(&message, MAX_REPORT_SIZE),
        Ok(AggregateReport::parse_xml(REPORT.as_bytes()).unwrap())
    );
    assert_eq!(
        AggregateReport::parse_rfc5322(&message, REPORT.len() - 1),
        Err(ReportError::TooLarge)
    );
}

#[test]
fn dmarc_report_gzip_bomb() {
    let bomb = gzip(&vec![b' '; 1024 * 1024]);
    let message = message_with_attachment("application/gzip", "report.xml.gz", &bomb);

    assert_eq!(
        AggregateReport::parse_rfc5322(&message, 64 * 1024),
        Err(ReportError::TooLarge)
    );
}

#[test]
fn dmarc_report_gzip_within_limit() {
    let message = message_with_attachment(
        "application/gzip",
        "report.xml.gz",
        &gzip(REPORT.as_bytes()),
    );

    assert_eq!(
        AggregateReport::parse_rfc5322(&message, MAX_REPORT_SIZE),
        Ok(AggregateReport::parse_xml(REPORT.as_bytes()).unwrap())
    );
    assert_eq!(
        AggregateReport::parse_rfc5322(&message, REPORT.len() - 1),
        Err(ReportError::TooLarge)
    );
}

#[test]
fn dmarc_report_unknown_top_level_element() {
    for xml in [
        REPORT.replace(
            "<feedback>",
            "<feedback><vendor><nested>x</nested></vendor>",
        ),
        REPORT.replace("</report_metadata>", "</report_metadata><vendor>x</vendor>"),
    ] {
        let report = AggregateReport::parse_xml(xml.as_bytes()).unwrap();
        assert_eq!(report.report_metadata.report_id, "1");
        assert_eq!(report.policy_published.domain, "example.org");
    }
}

#[test]
fn dmarc_report_version_serde() {
    use crate::report::dmarc::ReportVersion;

    assert_eq!(serde_json::to_string(&ReportVersion::V1).unwrap(), "1.0");
    for valid in ["1.0", "1", "\"1.0\"", "\" 1 \""] {
        assert_eq!(
            serde_json::from_str::<ReportVersion>(valid).unwrap(),
            ReportVersion::V1,
            "{valid}"
        );
    }
    assert!(serde_json::from_str::<ReportVersion>("2.0").is_err());

    let report = AggregateReport::parse_xml(REPORT.as_bytes()).unwrap();
    let mut json = serde_json::to_value(&report).unwrap();
    for (value, expected) in [
        (serde_json::json!(1.0), Some(ReportVersion::V1)),
        (serde_json::json!(1), Some(ReportVersion::V1)),
        (serde_json::json!("1.0"), Some(ReportVersion::V1)),
        (serde_json::json!(2.0), None),
        (serde_json::json!(0.0), None),
        (serde_json::json!(null), None),
    ] {
        json["version"] = value.clone();
        let parsed: AggregateReport = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(parsed.version, expected, "{value}");
    }
    json.as_object_mut().unwrap().remove("version");
    assert_eq!(
        serde_json::from_value::<AggregateReport>(json)
            .unwrap()
            .version,
        None
    );
}
