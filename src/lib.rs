/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

#[cfg(not(feature = "dns-doh"))]
pub(crate) use std::time::{Instant, SystemTime};
#[cfg(feature = "dns-doh")]
pub(crate) use web_time::{Instant, SystemTime};

#[cfg(feature = "arc")]
pub mod arc;
pub mod auth_results;
mod authenticator;
pub mod crypto;
pub mod dkim;
pub mod dkim2;
pub mod dmarc;
pub mod dns;
mod error;
pub mod headers;
pub mod iprev;
pub mod message;
pub mod mta_sts;
pub(crate) mod parse;
#[cfg(feature = "report")]
pub mod report;
pub(crate) mod sampling;
pub(crate) mod scan;
pub mod signer;
pub mod spf;
#[cfg(any(feature = "test", fuzzing))]
#[doc(hidden)]
pub mod testing;
pub(crate) mod utf8;

#[cfg(all(feature = "dns-hickory", feature = "dns-doh"))]
compile_error!(
    "features `dns-hickory` and `dns-doh` are mutually exclusive; enable only one DNS backend"
);
#[cfg(not(any(feature = "dns-hickory", feature = "dns-doh")))]
compile_error!("a DNS backend is required; enable feature `dns-hickory` or `dns-doh`");

pub use flate2;
#[cfg(not(feature = "dns-doh"))]
pub use hickory_resolver;
#[cfg(feature = "report")]
pub use zip;

#[cfg(feature = "arc")]
pub use arc::{ArcOutput, ArcResult};
pub use auth_results::{AuthenticationResults, ReceivedSpf};
pub use authenticator::MessageAuthenticator;
pub use dkim::{DkimOutput, DkimResult};
pub use dkim2::{Dkim2Output, Dkim2Result};
pub use dmarc::{DmarcOutput, DmarcResult};
pub use dns::{
    DnsCache, DnssecStatus, IpLookupStrategy, Mx, Negative, NoCache, Parameters, RecordSet,
    ResolverCache, TxtRecord,
};
pub use error::{DnsError, Error, Result};
pub use iprev::{IprevOutput, IprevResult};
pub use message::AuthenticatedMessage;
pub use spf::{SpfOutput, SpfResult};
