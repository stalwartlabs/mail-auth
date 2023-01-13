/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
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
