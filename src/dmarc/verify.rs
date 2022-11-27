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

        if from_domain.is_empty()
            || (spf_output.result != SPFResult::Pass
                && !dkim_output.iter().any(|o| o.result == DKIMResult::Pass))
        {
            // No domain found or no mechanism passed, skip DMARC.
            return DMARCOutput::default().with_domain(from_domain);
        }

        // Obtain DMARC policy
        let dmarc = match self.dmarc_tree_walk(from_domain).await {
            Ok(Some(dmarc)) => dmarc,
            Ok(None) => return DMARCOutput::default().with_domain(from_domain),
            Err(err) => {
                return DMARCOutput::default()
                    .with_domain(from_domain)
                    .with_result(err.into());
            }
        };

        let output = DMARCOutput {
            result: DMARCResult::None,
            domain: from_domain.to_string(),
            policy: dmarc.p,
            record: None,
        };

        // Check SPF and DKIM strict alignment
        if (spf_output.result == SPFResult::Pass && mail_from_domain == from_domain)
            || (dkim_output.iter().any(|o| {
                o.result == DKIMResult::Pass && o.signature.as_ref().unwrap().d.eq(from_domain)
            }))
        {
            output.with_record(dmarc).with_result(DMARCResult::Pass)
        } else if dmarc.adkim == Alignment::Strict && dmarc.aspf == Alignment::Strict {
            output
                .with_record(dmarc)
                .with_result(DMARCResult::Fail(Error::DMARCNotAligned))
        } else {
            // Check SPF relaxed alignment
            let from_subdomain = format!(".{}", from_domain);
            if (spf_output.result == SPFResult::Pass
                && dmarc.aspf == Alignment::Relaxed
                && (mail_from_domain.ends_with(&from_subdomain)
                    || from_domain.ends_with(&format!(".{}", mail_from_domain))))
                || (dmarc.adkim == Alignment::Relaxed
                    && dkim_output.iter().any(|o| {
                        o.result == DKIMResult::Pass
                            && (o.signature.as_ref().unwrap().d.ends_with(&from_subdomain)
                                || from_domain
                                    .ends_with(&format!(".{}", o.signature.as_ref().unwrap().d)))
                    }))
            {
                output
                    .with_policy(dmarc.sp)
                    .with_record(dmarc)
                    .with_result(DMARCResult::Pass)
            } else {
                output
                    .with_record(dmarc)
                    .with_result(DMARCResult::Fail(Error::DMARCNotAligned))
            }
        }
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
