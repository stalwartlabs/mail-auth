/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Helpers that fill a [`Record`] and a [`PolicyPublished`] from the outputs
//! of the DKIM, DKIM2, SPF, DMARC and ARC verifiers.

use super::PolicyPublished;
#[cfg(feature = "arc")]
use crate::ArcOutput;
#[cfg(feature = "arc")]
use crate::report::dmarc::{PolicyOverride, PolicyOverrideReason};
use crate::{
    Dkim2Result, DkimOutput, DmarcOutput, SpfOutput,
    dkim2::Dkim2Output,
    dmarc::{DmarcRecord, Policy},
    report::dmarc::{
        Discovery, Disposition, DkimAuthResult, DkimStatus, DmarcStatus, Record, SpfAuthResult,
        SpfScope, SpfStatus,
    },
};
#[cfg(feature = "arc")]
use std::fmt::Write;

impl Record {
    /// Appends one [`DkimAuthResult`] to `auth_results.dkim` for each DKIM
    /// output that carries a signature.
    ///
    /// The domain and selector come from the signature's `d=` and `s=` tags.
    /// For results other than `pass` and `none`, `human_result` holds the
    /// error text. Outputs without a signature are skipped.
    pub fn with_dkim_output(mut self, dkim_output: &[DkimOutput]) -> Self {
        for dkim in dkim_output {
            if let Some(signature) = &dkim.signature {
                let (result, human_result) = match &dkim.result {
                    crate::DkimResult::Pass => (DkimStatus::Pass, None),
                    crate::DkimResult::Neutral(err) => {
                        (DkimStatus::Neutral, err.to_string().into())
                    }
                    crate::DkimResult::Fail(err) => (DkimStatus::Fail, err.to_string().into()),
                    crate::DkimResult::PermError(err) => {
                        (DkimStatus::PermError, err.to_string().into())
                    }
                    crate::DkimResult::TempError(err) => {
                        (DkimStatus::TempError, err.to_string().into())
                    }
                    crate::DkimResult::None => (DkimStatus::None, None),
                };

                self.auth_results.dkim.push(DkimAuthResult {
                    domain: signature.d.to_string(),
                    selector: signature.s.to_string(),
                    result,
                    human_result,
                });
            }
        }
        self
    }

    /// Appends one [`DkimAuthResult`] to `auth_results.dkim` for each link of
    /// the DKIM2 signature chain.
    ///
    /// The domain comes from the signature's `d=` tag and the selector from its
    /// first `s=` entry (empty when there is none). For results other than
    /// `pass` and `none`, `human_result` holds the error text.
    pub fn with_dkim2_output(mut self, dkim2_output: &Dkim2Output) -> Self {
        for link in dkim2_output.chain() {
            let (result, human_result) = match &link.result {
                Dkim2Result::Pass => (DkimStatus::Pass, None),
                Dkim2Result::Fail(err) => (DkimStatus::Fail, err.to_string().into()),
                Dkim2Result::PermError(err) => (DkimStatus::PermError, err.to_string().into()),
                Dkim2Result::TempError(err) => (DkimStatus::TempError, err.to_string().into()),
                Dkim2Result::None => (DkimStatus::None, None),
            };

            self.auth_results.dkim.push(DkimAuthResult {
                domain: link.signature.d.to_string(),
                selector: link
                    .signature
                    .s
                    .first()
                    .map(|value| value.selector.clone())
                    .unwrap_or_default(),
                result,
                human_result,
            });
        }
        self
    }

    /// Appends one [`SpfAuthResult`] for `spf_output` to `auth_results.spf`.
    ///
    /// `scope` records which identity was checked (`HELO` or `MAIL FROM`) and
    /// is stored as given. `human_result` is left empty.
    pub fn with_spf_output(mut self, spf_output: &SpfOutput, scope: SpfScope) -> Self {
        self.auth_results.spf.push(SpfAuthResult {
            domain: spf_output.domain.to_string(),
            scope,
            result: match spf_output.result {
                crate::SpfResult::Pass => SpfStatus::Pass,
                crate::SpfResult::Fail => SpfStatus::Fail,
                crate::SpfResult::SoftFail => SpfStatus::SoftFail,
                crate::SpfResult::Neutral => SpfStatus::Neutral,
                crate::SpfResult::TempError => SpfStatus::TempError,
                crate::SpfResult::PermError => SpfStatus::PermError,
                crate::SpfResult::None => SpfStatus::None,
            },
            human_result: None,
        });
        self
    }

    /// Sets `row.policy_evaluated` from a DMARC verification result.
    ///
    /// The `dkim` and `spf` statuses are [`DmarcStatus::Pass`] when the aligned
    /// result passed and [`DmarcStatus::Fail`] otherwise. The disposition is
    /// [`Disposition::Pass`] when either passed; otherwise it follows the
    /// policy in `dmarc_output` (`none` when the policy is unspecified).
    /// Override reasons are left untouched.
    pub fn with_dmarc_output(mut self, dmarc_output: &DmarcOutput) -> Self {
        self.row.policy_evaluated.disposition = if dmarc_output.dkim_result
            == crate::DmarcResult::Pass
            || dmarc_output.spf_result == crate::DmarcResult::Pass
        {
            Disposition::Pass
        } else {
            match dmarc_output.policy {
                Policy::None | Policy::Unspecified => Disposition::None,
                Policy::Quarantine => Disposition::Quarantine,
                Policy::Reject => Disposition::Reject,
            }
        };
        self.row.policy_evaluated.dkim = (&dmarc_output.dkim_result).into();
        self.row.policy_evaluated.spf = (&dmarc_output.spf_result).into();
        self
    }

    /// Records a passing ARC chain as a policy override reason (feature `arc`).
    ///
    /// When the ARC result is `pass`, appends a [`PolicyOverride::LocalPolicy`]
    /// reason whose comment reads `arc=pass` followed by the `d=` and `s=`
    /// tags of every ARC-Seal, in reverse chain order, as `as[i].d=... as[i].s=...`.
    /// Any other ARC result leaves the record unchanged.
    #[cfg(feature = "arc")]
    pub fn with_arc_output(mut self, arc_output: &ArcOutput) -> Self {
        if arc_output.result == crate::DkimResult::Pass {
            let mut comment = "arc=pass".to_string();
            for set in arc_output.set.iter().rev() {
                let seal = &set.seal.header;
                write!(
                    &mut comment,
                    " as[{}].d={} as[{}].s={}",
                    seal.i, seal.d, seal.i, seal.s
                )
                .ok();
            }
            self.row.policy_evaluated.reason.push(PolicyOverrideReason {
                kind: PolicyOverride::LocalPolicy,
                comment: Some(comment),
            });
        }
        self
    }
}

impl PolicyPublished {
    /// Builds the `policy_published` element for `domain` from its parsed
    /// DMARC record.
    ///
    /// Copies `adkim`, `aspf`, `p`, `sp`, `np` (an unspecified policy becomes
    /// `none`), `testing` from the `t` tag and `fo` in its tag syntax (`0`,
    /// `1`, `d`, `s` or `d:s`). The discovery method is set to
    /// [`Discovery::Treewalk`] and `version_published` to `None`.
    pub fn from_record(domain: impl Into<String>, dmarc: &DmarcRecord) -> Self {
        PolicyPublished {
            domain: domain.into(),
            adkim: Some(dmarc.adkim),
            aspf: Some(dmarc.aspf),
            p: published_policy(dmarc.p),
            sp: published_policy(dmarc.sp),
            np: published_policy(dmarc.np),
            testing: dmarc.t,
            discovery_method: Discovery::Treewalk,
            fo: match &dmarc.fo {
                crate::dmarc::FailureOptions::All => "0",
                crate::dmarc::FailureOptions::Any => "1",
                crate::dmarc::FailureOptions::Dkim => "d",
                crate::dmarc::FailureOptions::Spf => "s",
                crate::dmarc::FailureOptions::DkimSpf => "d:s",
            }
            .to_string()
            .into(),
            version_published: None,
        }
    }
}

impl From<&crate::DmarcResult> for DmarcStatus {
    fn from(result: &crate::DmarcResult) -> Self {
        match result {
            crate::DmarcResult::Pass => DmarcStatus::Pass,
            _ => DmarcStatus::Fail,
        }
    }
}

fn published_policy(policy: Policy) -> Policy {
    match policy {
        Policy::Unspecified => Policy::None,
        policy => policy,
    }
}
