/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! ML-DSA-44 with a signature context string, through the AWS-LC `EVP` API.
//! `aws-lc-rs` only exposes ML-DSA with an empty context, which DKIM2 cannot
//! use.

use super::mldsa::{PUBLIC_KEY_LEN, SIGNATURE_LEN, Seed};
use aws_lc_sys::{
    EVP_DigestSign, EVP_DigestSignInit, EVP_DigestVerify, EVP_DigestVerifyInit, EVP_MD_CTX,
    EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_PKEY, EVP_PKEY_CTX,
    EVP_PKEY_CTX_set1_signature_context_string, EVP_PKEY_free, EVP_PKEY_get_raw_public_key,
    EVP_PKEY_pqdsa_new_raw_private_key, EVP_PKEY_pqdsa_new_raw_public_key, NID_MLDSA44,
};
use std::ptr::{NonNull, null, null_mut};

const SUCCESS: i32 = 1;

pub(crate) struct MlDsa44(NonNull<EVP_PKEY>);

// SAFETY: the EVP_PKEY is never mutated after construction and its reference count is atomic, so ownership can move across threads.
unsafe impl Send for MlDsa44 {}
// SAFETY: all methods take &self and only read the EVP_PKEY (each call uses its own EVP_MD_CTX), and its reference count is atomic.
unsafe impl Sync for MlDsa44 {}

impl Drop for MlDsa44 {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid EVP_PKEY owned by this value and released only here.
        unsafe { EVP_PKEY_free(self.0.as_ptr()) }
    }
}

impl MlDsa44 {
    pub(crate) fn from_seed(seed: &Seed) -> Option<Self> {
        // SAFETY: seed is a 32-byte array, the ML-DSA-44 keygen seed length, readable for seed.len() bytes; a null return is handled by NonNull::new.
        NonNull::new(unsafe {
            EVP_PKEY_pqdsa_new_raw_private_key(NID_MLDSA44, seed.as_ptr(), seed.len())
        })
        .map(Self)
    }

    pub(crate) fn from_public_key(key: &[u8; PUBLIC_KEY_LEN]) -> Option<Self> {
        // SAFETY: key is readable for PUBLIC_KEY_LEN bytes, which AWS-LC copies; a null return is handled by NonNull::new.
        NonNull::new(unsafe {
            EVP_PKEY_pqdsa_new_raw_public_key(NID_MLDSA44, key.as_ptr(), key.len())
        })
        .map(Self)
    }

    pub(crate) fn public_key(&self) -> Option<[u8; PUBLIC_KEY_LEN]> {
        let mut key = [0u8; PUBLIC_KEY_LEN];
        let mut len = key.len();
        // SAFETY: self.0 is a valid EVP_PKEY and key is writable for len bytes (its capacity), so at most len bytes are written; status and len are checked.
        let status =
            unsafe { EVP_PKEY_get_raw_public_key(self.0.as_ptr(), key.as_mut_ptr(), &mut len) };
        (status == SUCCESS && len == PUBLIC_KEY_LEN).then_some(key)
    }

    pub(crate) fn sign(&self, message: &[u8], context: &[u8]) -> Option<[u8; SIGNATURE_LEN]> {
        let ctx = DigestContext::new()?;
        let pctx = ctx.init(self, Operation::Sign)?;
        let mut signature = [0u8; SIGNATURE_LEN];
        let mut len = signature.len();
        // SAFETY: ctx is live and initialized for signing, and pctx is owned by ctx; context, message and signature are valid for their lengths, with len set to the
        // capacity of signature (AWS-LC copies the context and rejects more than 255 bytes); both return codes are checked.
        let status = unsafe {
            if EVP_PKEY_CTX_set1_signature_context_string(pctx, context.as_ptr(), context.len())
                != SUCCESS
            {
                return None;
            }
            EVP_DigestSign(
                ctx.0.as_ptr(),
                signature.as_mut_ptr(),
                &mut len,
                message.as_ptr(),
                message.len(),
            )
        };
        (status == SUCCESS && len == SIGNATURE_LEN).then_some(signature)
    }

    pub(crate) fn verify(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &[u8; SIGNATURE_LEN],
    ) -> bool {
        let Some(ctx) = DigestContext::new() else {
            return false;
        };
        let Some(pctx) = ctx.init(self, Operation::Verify) else {
            return false;
        };
        // SAFETY: ctx is live and initialized for verification, and pctx is owned by ctx; context, message and signature are valid for their lengths (AWS-LC copies the
        // context and rejects a signature of the wrong length); both return codes are checked.
        unsafe {
            EVP_PKEY_CTX_set1_signature_context_string(pctx, context.as_ptr(), context.len())
                == SUCCESS
                && EVP_DigestVerify(
                    ctx.0.as_ptr(),
                    signature.as_ptr(),
                    signature.len(),
                    message.as_ptr(),
                    message.len(),
                ) == SUCCESS
        }
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Sign,
    Verify,
}

struct DigestContext(NonNull<EVP_MD_CTX>);

impl DigestContext {
    fn new() -> Option<Self> {
        // SAFETY: EVP_MD_CTX_new takes no arguments; a null return is handled by NonNull::new.
        NonNull::new(unsafe { EVP_MD_CTX_new() }).map(Self)
    }

    fn init(&self, key: &MlDsa44, operation: Operation) -> Option<*mut EVP_PKEY_CTX> {
        let mut pctx: *mut EVP_PKEY_CTX = null_mut();
        // SAFETY: self.0 and key.0 are valid, pctx is a valid out pointer and a null digest and engine are accepted for ML-DSA pure mode;
        // the returned pctx is owned by self.0 and checked for null.
        let status = unsafe {
            match operation {
                Operation::Sign => EVP_DigestSignInit(
                    self.0.as_ptr(),
                    &mut pctx,
                    null(),
                    null_mut(),
                    key.0.as_ptr(),
                ),
                Operation::Verify => EVP_DigestVerifyInit(
                    self.0.as_ptr(),
                    &mut pctx,
                    null(),
                    null_mut(),
                    key.0.as_ptr(),
                ),
            }
        };
        (status == SUCCESS && !pctx.is_null()).then_some(pctx)
    }
}

impl Drop for DigestContext {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid EVP_MD_CTX from EVP_MD_CTX_new, owned by this value and freed only here, which also frees its EVP_PKEY_CTX.
        unsafe { EVP_MD_CTX_free(self.0.as_ptr()) }
    }
}
