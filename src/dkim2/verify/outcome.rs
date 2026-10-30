/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Combination of intermediate signature and hash results over the `,`
//! (all) and `|` (any) groups of the `s=` and `h=` tags (§14.6 and §14.7).

use crate::{Dkim2Result, Error, dkim2::Dkim2Error};

/// A result other than PASS, with the error that explains it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    TempError(Dkim2Error),
    Fail(Dkim2Error),
    PermError(Dkim2Error),
}

impl Failure {
    pub(crate) fn into_error(self) -> Dkim2Error {
        match self {
            Failure::TempError(error) | Failure::Fail(error) | Failure::PermError(error) => error,
        }
    }
}

impl From<Failure> for Dkim2Result {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::TempError(error) => Dkim2Result::TempError(Error::Dkim2(error)),
            Failure::Fail(error) => Dkim2Result::Fail(Error::Dkim2(error)),
            Failure::PermError(error) => Dkim2Result::PermError(Error::Dkim2(error)),
        }
    }
}

/// Intermediate results of the members of a group, keeping the first error
/// of each kind.
#[derive(Default)]
pub(crate) struct Tally {
    members: u32,
    passed: bool,
    temp_error: Option<Dkim2Error>,
    fail: Option<Dkim2Error>,
    perm_error: Option<Dkim2Error>,
}

impl Tally {
    pub(crate) fn record(&mut self, outcome: Result<(), Failure>) {
        self.members = self.members.saturating_add(1);
        match outcome {
            Ok(()) => self.passed = true,
            Err(Failure::TempError(error)) => {
                self.temp_error.get_or_insert(error);
            }
            Err(Failure::Fail(error)) => {
                self.fail.get_or_insert(error);
            }
            Err(Failure::PermError(error)) => {
                self.perm_error.get_or_insert(error);
            }
        }
    }

    pub(crate) fn passed(&self) -> bool {
        self.passed
    }

    pub(crate) fn failed(&self) -> bool {
        self.fail.is_some()
    }

    pub(crate) fn all(self) -> Result<(), Failure> {
        match (self.temp_error, self.fail, self.perm_error) {
            (None, None, None) => Ok(()),
            (Some(error), None, None) => Err(Failure::TempError(error)),
            (_, Some(error), _) => Err(Failure::Fail(error)),
            (_, None, Some(error)) => Err(Failure::PermError(error)),
        }
    }

    pub(crate) fn any(self, no_group_passed: Dkim2Error) -> Result<(), Failure> {
        if self.passed {
            Ok(())
        } else if let Some(error) = self.temp_error {
            Err(Failure::TempError(error))
        } else if let Some(error) = self.fail {
            Err(Failure::Fail(if self.members > 1 {
                no_group_passed
            } else {
                error
            }))
        } else {
            Err(Failure::PermError(
                self.perm_error.unwrap_or(no_group_passed),
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn temp() -> Result<(), Failure> {
        Err(Failure::TempError(Dkim2Error::SequenceGap(1)))
    }

    fn fail() -> Result<(), Failure> {
        Err(Failure::Fail(Dkim2Error::SequenceGap(2)))
    }

    fn perm() -> Result<(), Failure> {
        Err(Failure::PermError(Dkim2Error::SequenceGap(3)))
    }

    fn tally(outcomes: impl IntoIterator<Item = Result<(), Failure>>) -> Tally {
        let mut tally = Tally::default();
        for outcome in outcomes {
            tally.record(outcome);
        }
        tally
    }

    // The sig-all rules of §14.6 step 6.
    #[test]
    fn all_rules() {
        assert_eq!(tally([Ok(()), Ok(())]).all(), Ok(()));
        assert_eq!(tally([Ok(()), temp()]).all(), temp());
        assert_eq!(tally([temp(), fail(), perm()]).all(), fail());
        assert_eq!(tally([temp(), perm()]).all(), perm());
        assert_eq!(tally([Ok(()), perm()]).all(), perm());
    }

    // The sig-any rules of §14.6 step 7: TEMPERROR beats FAIL, which beats PERMERROR.
    #[test]
    fn any_rules() {
        let none = || Dkim2Error::NoSignatureGroupPassed(9);
        assert_eq!(tally([perm(), Ok(())]).any(none()), Ok(()));
        assert_eq!(tally([fail(), temp(), perm()]).any(none()), temp());
        assert_eq!(
            tally([perm(), fail()]).any(none()),
            Err(Failure::Fail(none()))
        );
        assert_eq!(tally([fail()]).any(none()), fail());
        assert_eq!(tally([perm(), perm()]).any(none()), perm());
        assert_eq!(
            Tally::default().any(none()),
            Err(Failure::PermError(none()))
        );
    }
}
