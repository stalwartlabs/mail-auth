use crate::AuthenticatedMessage;

use super::headers::Header;

impl<'x> AuthenticatedMessage<'x> {
    #[inline(always)]
    pub fn new(_raw_message: &'x [u8]) -> Option<Self> {
        None
    }
}

impl<'x, T> Header<'x, T> {
    pub fn new(name: &'x [u8], value: &'x [u8], header: T) -> Self {
        Header {
            name,
            value,
            header,
        }
    }
}
