//! Thin wrapper around `CryptProtectData` / `CryptUnprotectData`.
//! This is the only place in Penmark that calls the Windows API directly.

#![allow(unsafe_code)]

use std::io;
use std::ptr;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::Zeroizing;

/// Extra secret mixed in by DPAPI: a blob sealed for another program with the
/// same Windows account cannot be opened as a Penmark key, and vice versa.
const ENTROPY: &[u8] = b"Penmark signing key v1";

fn blob(data: &[u8]) -> io::Result<CRYPT_INTEGER_BLOB> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "data too large for DPAPI"))?;
    Ok(CRYPT_INTEGER_BLOB {
        cbData: len,
        // DPAPI only reads the input buffers; the cast is required by the C signature.
        pbData: data.as_ptr().cast_mut(),
    })
}

/// Encrypts `plain` for the current Windows user.
pub(crate) fn protect(plain: &[u8]) -> io::Result<Vec<u8>> {
    let input = blob(plain)?;
    let entropy = blob(ENTROPY)?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` and `entropy` point to slices that outlive the call;
    // the optional description, reserved and prompt pointers may be null;
    // `out` is filled by the OS and released with LocalFree below.
    let ok = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success `out.pbData` points to `out.cbData` bytes owned by us.
    let sealed = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    // SAFETY: the buffer was allocated by DPAPI with LocalAlloc.
    unsafe { LocalFree(out.pbData.cast()) };
    Ok(sealed)
}

/// Decrypts a blob made by [`protect`] for the current Windows user.
pub(crate) fn unprotect(sealed: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let input = blob(sealed)?;
    let entropy = blob(ENTROPY)?;
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: same contract as in `protect`; the description out-pointer is null.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let len = out.cbData as usize;
    // SAFETY: on success `out.pbData` points to `len` bytes owned by us.
    let plain = Zeroizing::new(unsafe { std::slice::from_raw_parts(out.pbData, len) }.to_vec());
    // SAFETY: wipe the OS copy of the secret, then free it (LocalAlloc'd).
    unsafe {
        ptr::write_bytes(out.pbData, 0, len);
        LocalFree(out.pbData.cast());
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let secret = [7u8; 32];
        let sealed = protect(&secret).unwrap();
        assert_ne!(&sealed[..], &secret[..]);
        assert!(sealed.windows(32).all(|w| w != secret));
        let back = unprotect(&sealed).unwrap();
        assert_eq!(&back[..], &secret[..]);
    }

    #[test]
    fn tampered_blob_is_refused() {
        let mut sealed = protect(&[9u8; 32]).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(unprotect(&sealed).is_err());
    }

    #[test]
    fn garbage_is_refused() {
        assert!(unprotect(b"not a dpapi blob").is_err());
    }
}
