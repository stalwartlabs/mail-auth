use std::sync::Arc;

use crate::{
    AuthenticatedMessage, DKIMOutput, DKIMResult, DMARCOutput, DMARCResult, Error, Resolver,
    SPFOutput, SPFResult,
};

use super::{Alignment, DMARC};

impl Resolver {
    pub async fn verify_dmarc(
        &self,
        message: &AuthenticatedMessage<'_>,
        dkim_output: &[DKIMOutput<'_>],
        mail_from_domain: &str,
        spf_output: &SPFOutput,
    ) -> DMARCOutput {
        // Extract RFC5322.From
        let mut from_domain = "";
        for from in &message.from {
            if let Some((_, domain)) = from.rsplit_once('@') {
                if from_domain.is_empty() {
                    from_domain = domain;
                } else if from_domain != domain {
                    // Multi-valued RFC5322.From header fields with multiple
                    // domains MUST be exempt from DMARC checking.
                    return DMARCOutput::default();
                }
            }
        }

        let has_dkim_pass = dkim_output.iter().any(|o| o.result == DKIMResult::Pass);
        if from_domain.is_empty() || (spf_output.result != SPFResult::Pass && !has_dkim_pass) {
            // No domain found or no mechanism passed, skip DMARC.
            return DMARCOutput::default().with_domain(from_domain);
        }

        // Obtain DMARC policy
        let dmarc = match self.dmarc_tree_walk(from_domain).await {
            Ok(Some(dmarc)) => dmarc,
            Ok(None) => return DMARCOutput::default().with_domain(from_domain),
            Err(err) => {
                let err = DMARCResult::from(err);
                return DMARCOutput::default()
                    .with_domain(from_domain)
                    .with_dkim_result(err.clone())
                    .with_spf_result(err);
            }
        };

        let mut output = DMARCOutput {
            spf_result: DMARCResult::None,
            dkim_result: DMARCResult::None,
            domain: from_domain.to_string(),
            policy: dmarc.p,
            record: None,
        };

        // Check SPF alignment
        let from_subdomain = format!(".{}", from_domain);
        if spf_output.result == SPFResult::Pass {
            output.spf_result = if mail_from_domain == from_domain {
                DMARCResult::Pass
            } else if dmarc.aspf == Alignment::Relaxed
                && mail_from_domain.ends_with(&from_subdomain)
                || from_domain.ends_with(&format!(".{}", mail_from_domain))
            {
                output.policy = dmarc.sp;
                DMARCResult::Pass
            } else {
                DMARCResult::Fail(Error::DMARCNotAligned)
            };
        }

        // Check DKIM alignment
        if has_dkim_pass {
            output.dkim_result = if dkim_output.iter().any(|o| {
                o.result == DKIMResult::Pass && o.signature.as_ref().unwrap().d.eq(from_domain)
            }) {
                DMARCResult::Pass
            } else if dmarc.adkim == Alignment::Relaxed
                && dkim_output.iter().any(|o| {
                    o.result == DKIMResult::Pass
                        && (o.signature.as_ref().unwrap().d.ends_with(&from_subdomain)
                            || from_domain
                                .ends_with(&format!(".{}", o.signature.as_ref().unwrap().d)))
                })
            {
                output.policy = dmarc.sp;
                DMARCResult::Pass
            } else {
                DMARCResult::Fail(Error::DMARCNotAligned)
            };
        }

        output.with_record(dmarc)
    }

    async fn dmarc_tree_walk(&self, domain: &str) -> crate::Result<Option<Arc<DMARC>>> {
        let labels = domain.split('.').collect::<Vec<_>>();
        let mut x = labels.len();
        if x == 1 {
            return Ok(None);
        }
        while x != 0 {
            // Build query domain
            let mut domain = String::with_capacity(domain.len() + 8);
            domain.push_str("_dmarc");
            for label in labels.iter().skip(labels.len() - x) {
                domain.push('.');
                domain.push_str(label);
            }
            domain.push('.');

            // Query DMARC
            match self.txt_lookup::<DMARC>(domain).await {
                Ok(dmarc) => {
                    return Ok(Some(dmarc));
                }
                Err(Error::DNSRecordNotFound(_)) | Err(Error::InvalidRecordType) => (),
                Err(err) => return Err(err),
            }

            // If x < 5, remove the left-most (highest-numbered) label from the subject domain.
            // If x >= 5, remove the left-most (highest-numbered) labels from the subject
            // domain until 4 labels remain.
            if x < 5 {
                x -= 1;
            } else {
                x = 4;
            }
        }

        Ok(None)
    }
}
