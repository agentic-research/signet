//! C FFI for CMS/PKCS#7 signing and verification.
//!
//! Buffer-based API, return conventions:
//! - `>= 0`: bytes written to output buffer
//! - `-1`: error (signing/verification failed, buffer too small, null pointer)

use crate::cms;

/// Build a slice from a pointer + length, returning an empty slice for zero-length inputs.
/// Returns `None` if the pointer is null with a non-zero length.
unsafe fn safe_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Helper: write bytes into an output buffer, returning byte count or -1 on error.
unsafe fn write_out(data: &[u8], out_buf: *mut u8, out_len: usize) -> i32 {
    let len = data.len();
    if len > out_len {
        return -1;
    }
    if len == 0 {
        return 0;
    }
    if len > i32::MAX as usize {
        return -1;
    }
    if out_buf.is_null() {
        return -1;
    }
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), out_buf, len) };
    len as i32
}

/// Sign data with CMS/PKCS#7 using Ed25519 and signed attributes.
///
/// Returns >= 0 (bytes written to out_buf) on success, -1 on error.
///
/// # Safety
/// All pointers must be valid for their stated lengths.
/// `private_key_ptr` must point to exactly 64 bytes (Ed25519 keypair).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signet_sign_data(
    data_ptr: *const u8,
    data_len: usize,
    cert_der_ptr: *const u8,
    cert_der_len: usize,
    private_key_ptr: *const u8,
    out_buf: *mut u8,
    out_len: usize,
) -> i32 {
    let Some(data) = (unsafe { safe_slice(data_ptr, data_len) }) else {
        return -1;
    };
    let Some(cert_der) = (unsafe { safe_slice(cert_der_ptr, cert_der_len) }) else {
        return -1;
    };
    let Some(key_slice) = (unsafe { safe_slice(private_key_ptr, 64) }) else {
        return -1;
    };
    let mut key: [u8; 64] = match key_slice.try_into() {
        Ok(k) => k,
        Err(_) => return -1,
    };

    let result = match cms::sign_data(data, cert_der, &key) {
        Ok(sig) => unsafe { write_out(&sig, out_buf, out_len) },
        Err(_) => -1,
    };
    // Zeroize the key copy before returning
    key.fill(0);
    result
}

/// Sign data with CMS/PKCS#7 using Ed25519 PureEdDSA (no signed attributes).
///
/// Returns >= 0 (bytes written to out_buf) on success, -1 on error.
///
/// # Safety
/// All pointers must be valid for their stated lengths.
/// `private_key_ptr` must point to exactly 64 bytes (Ed25519 keypair).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signet_sign_data_without_attributes(
    data_ptr: *const u8,
    data_len: usize,
    cert_der_ptr: *const u8,
    cert_der_len: usize,
    private_key_ptr: *const u8,
    out_buf: *mut u8,
    out_len: usize,
) -> i32 {
    let Some(data) = (unsafe { safe_slice(data_ptr, data_len) }) else {
        return -1;
    };
    let Some(cert_der) = (unsafe { safe_slice(cert_der_ptr, cert_der_len) }) else {
        return -1;
    };
    let Some(key_slice) = (unsafe { safe_slice(private_key_ptr, 64) }) else {
        return -1;
    };
    let mut key: [u8; 64] = match key_slice.try_into() {
        Ok(k) => k,
        Err(_) => return -1,
    };

    let result = match cms::sign_data_without_attributes(data, cert_der, &key) {
        Ok(sig) => unsafe { write_out(&sig, out_buf, out_len) },
        Err(_) => -1,
    };
    key.fill(0);
    result
}

/// Verify a CMS/PKCS#7 detached signature.
///
/// On success, writes the signer certificate DER to `cert_out_buf` and returns
/// the number of bytes written (>= 0). Returns -1 on verification failure.
///
/// # Safety
/// All pointers must be valid for their stated lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signet_verify(
    cms_sig_ptr: *const u8,
    cms_sig_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    cert_out_buf: *mut u8,
    cert_out_len: usize,
) -> i32 {
    let Some(cms_sig) = (unsafe { safe_slice(cms_sig_ptr, cms_sig_len) }) else {
        return -1;
    };
    let Some(data) = (unsafe { safe_slice(data_ptr, data_len) }) else {
        return -1;
    };

    match cms::verify(cms_sig, data, &cms::VerifyOptions::default()) {
        Ok(cert_der) => unsafe { write_out(&cert_der, cert_out_buf, cert_out_len) },
        Err(_) => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    /// Reuse the test cert builder from cms module.
    fn generate_test_cert_and_key() -> (Vec<u8>, [u8; 64]) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let cert_der = crate::cms::tests::build_self_signed_cert(&signing_key);
        let keypair_bytes = signing_key.to_keypair_bytes();
        (cert_der, keypair_bytes)
    }

    #[test]
    fn ffi_sign_and_verify() {
        let (cert_der, key) = generate_test_cert_and_key();
        let data = b"FFI round-trip test";

        let mut sig_buf = vec![0u8; 4096];
        let sig_len = unsafe {
            signet_sign_data(
                data.as_ptr(),
                data.len(),
                cert_der.as_ptr(),
                cert_der.len(),
                key.as_ptr(),
                sig_buf.as_mut_ptr(),
                sig_buf.len(),
            )
        };
        assert!(sig_len > 0, "signing should succeed, got {}", sig_len);

        let mut cert_buf = vec![0u8; 4096];
        let cert_len = unsafe {
            signet_verify(
                sig_buf.as_ptr(),
                sig_len as usize,
                data.as_ptr(),
                data.len(),
                cert_buf.as_mut_ptr(),
                cert_buf.len(),
            )
        };
        assert!(
            cert_len > 0,
            "verification should succeed, got {}",
            cert_len
        );
        assert_eq!(&cert_buf[..cert_len as usize], &cert_der);
    }

    #[test]
    fn ffi_buffer_too_small() {
        let (cert_der, key) = generate_test_cert_and_key();
        let data = b"test";

        // Tiny buffer should return -1
        let mut sig_buf = vec![0u8; 10];
        let sig_len = unsafe {
            signet_sign_data(
                data.as_ptr(),
                data.len(),
                cert_der.as_ptr(),
                cert_der.len(),
                key.as_ptr(),
                sig_buf.as_mut_ptr(),
                sig_buf.len(),
            )
        };
        assert_eq!(sig_len, -1, "should fail with small buffer");
    }
}
