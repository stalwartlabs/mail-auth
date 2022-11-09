pub mod parse;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DMARC {
    adkim: Alignment,
    aspf: Alignment,
    fo: Report,
    np: Policy,
    p: Policy,
    pct: u8,
    rf: u8,
    ri: u32,
    rua: Vec<URI>,
    ruf: Vec<URI>,
    sp: Policy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct URI {
    uri: Vec<u8>,
    max_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Alignment {
    Relaxed,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Report {
    All,
    Any,
    Dkim,
    Spf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Policy {
    None,
    Quarantine,
    Reject,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Format {
    Afrf = 1,
}

impl From<Format> for u64 {
    fn from(f: Format) -> Self {
        f as u64
    }
}

impl URI {
    #[cfg(test)]
    pub fn new(uri: impl Into<String>, max_size: usize) -> Self {
        URI {
            uri: uri.into().into_bytes(),
            max_size,
        }
    }
}
