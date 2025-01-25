/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use serde::{Deserialize, Serialize};

pub mod parse;

#[derive(Debug, PartialEq, Eq)]
pub struct MtaSts {
    pub id: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsRpt {
    pub rua: Vec<ReportUri>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportUri {
    Mail(String),
    Http(String),
}
