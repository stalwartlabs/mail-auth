/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::SystemTime;
use std::cell::Cell;

thread_local!(static COUNTER: Cell<u64>  = const { Cell::new(0) });

/// Generates a random value between 0 and 100.
/// Returns true if the generated value is within the requested
/// sampling percentage specified in a SPF, DKIM or DMARC policy.
pub(crate) fn is_within_pct(pct: u8) -> bool {
    pct == 100
        || COUNTER.with(|c| {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                .wrapping_add(c.replace(c.get() + 1))
                .wrapping_mul(11400714819323198485u64)
        }) % 100
            < pct as u64
}
