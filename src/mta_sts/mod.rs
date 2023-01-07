/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

pub mod parse;

#[derive(Debug, PartialEq, Eq)]
pub struct MtaSts {
    pub id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TlsRpt {
    rua: Vec<ReportUri>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReportUri {
    Mail(String),
    Http(String),
}
