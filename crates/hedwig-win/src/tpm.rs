//! Keys in the workstation's TPM, through Windows' Platform Crypto Provider:
//! made, listed by name, read for their public half, signed with and
//! deleted. A key's private half never leaves the TPM, and no call here
//! raises a window: every one is made silent, so a key that would ask for
//! anything fails instead.

use std::fmt;

use windows_sys::Win32::Foundation::{
    E_INVALIDARG, NTE_BAD_KEYSET, NTE_EXISTS, NTE_INVALID_PARAMETER, NTE_NO_MORE_ITEMS,
    NTE_NOT_FOUND, NTE_NOT_SUPPORTED,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
    BCRYPT_ECDSA_PUBLIC_P384_MAGIC, BCRYPT_ECDSA_PUBLIC_P521_MAGIC, BCRYPT_PKCS1_PADDING_INFO,
    BCRYPT_RSAKEY_BLOB, BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSAPUBLIC_MAGIC, BCRYPT_SHA256_ALG_HANDLE,
    BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALG_HANDLE, BCRYPT_SHA384_ALGORITHM,
    BCRYPT_SHA512_ALG_HANDLE, BCRYPT_SHA512_ALGORITHM, BCryptHash, CERT_KEY_SPEC,
    MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_ECDSA_P384_ALGORITHM,
    NCRYPT_ECDSA_P521_ALGORITHM, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE,
    NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_RSA_ALGORITHM,
    NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptEnumKeys, NCryptExportKey,
    NCryptFinalizeKey, NCryptFreeBuffer, NCryptFreeObject, NCryptGetProperty, NCryptKeyName,
    NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};

use crate::raw::wide;

/// What a key is made as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Algorithm {
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Rsa { bits: u32 },
}

/// A key's public half, as the provider gives it: big-endian integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Public {
    Ecdsa {
        /// 256, 384 or 521.
        curve: u32,
        x: Vec<u8>,
        y: Vec<u8>,
    },
    Rsa {
        exponent: Vec<u8>,
        modulus: Vec<u8>,
    },
}

/// The digest a signature is made over, and the hash an RSA signature names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

/// How a digest is signed: as it is, for ECDSA, or in PKCS #1 v1.5 naming
/// its hash, for RSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Padding {
    None,
    Pkcs1(Hash),
}

/// How the provider failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmError {
    /// The provider would not open: no TPM, or none it can use.
    Unavailable(i32),
    /// The TPM does not make a key of this algorithm or length.
    Unsupported,
    /// A key of that name exists already.
    Exists,
    /// No key of that name.
    Missing,
    /// The provider failed otherwise, with this code.
    Failed(i32),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::Unavailable(code) => {
                write!(f, "the TPM's provider would not open ({code:#010x})")
            }
            TpmError::Unsupported => f.write_str("the TPM does not make that key"),
            TpmError::Exists => f.write_str("a key of that name exists"),
            TpmError::Missing => f.write_str("no key of that name"),
            TpmError::Failed(code) => write!(f, "the TPM's provider failed ({code:#010x})"),
        }
    }
}

impl std::error::Error for TpmError {}

fn checked(status: i32, otherwise: impl Fn(i32) -> TpmError) -> Result<(), TpmError> {
    match status {
        0 => Ok(()),
        NTE_EXISTS => Err(TpmError::Exists),
        NTE_BAD_KEYSET | NTE_NOT_FOUND => Err(TpmError::Missing),
        other => Err(otherwise(other)),
    }
}

/// An open storage provider.
#[derive(Debug)]
pub struct Provider(NCRYPT_PROV_HANDLE);

impl Drop for Provider {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by this value and is freed once.
        unsafe { NCryptFreeObject(self.0) };
    }
}

/// An open key.
#[derive(Debug)]
pub struct Key(NCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle was opened by this value and is freed once.
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

impl Provider {
    /// The Microsoft Platform Crypto Provider: the workstation's TPM.
    ///
    /// # Errors
    ///
    /// [`TpmError::Unavailable`] where it will not open.
    pub fn platform() -> Result<Provider, TpmError> {
        let mut handle: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: the out pointer is valid; the name is a static wide string.
        let status =
            unsafe { NCryptOpenStorageProvider(&raw mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
        checked(status, TpmError::Unavailable)?;
        Ok(Provider(handle))
    }

    /// The provider registered under `name`.
    ///
    /// # Errors
    ///
    /// [`TpmError::Unavailable`] where none is, or it will not open.
    pub fn named(name: &str) -> Result<Provider, TpmError> {
        let name = wide(name);
        let mut handle: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: the out pointer is valid; `name` is NUL-terminated.
        let status = unsafe { NCryptOpenStorageProvider(&raw mut handle, name.as_ptr(), 0) };
        checked(status, TpmError::Unavailable)?;
        Ok(Provider(handle))
    }

    /// The names of the person's keys here that begin with `prefix`. Every
    /// other name is passed over unopened.
    ///
    /// # Errors
    ///
    /// The provider failing to list.
    pub fn names(&self, prefix: &str) -> Result<Vec<String>, TpmError> {
        let mut names = Vec::new();
        let mut state: *mut core::ffi::c_void = std::ptr::null_mut();
        let outcome = loop {
            let mut entry: *mut NCryptKeyName = std::ptr::null_mut();
            // SAFETY: the out pointers are valid; `state` is the provider's
            // own, carried between calls and freed below.
            let status = unsafe {
                NCryptEnumKeys(
                    self.0,
                    std::ptr::null(),
                    &raw mut entry,
                    &raw mut state,
                    NCRYPT_SILENT_FLAG,
                )
            };
            if status == NTE_NO_MORE_ITEMS {
                break Ok(());
            }
            if let Err(error) = checked(status, TpmError::Failed) {
                break Err(error);
            }
            // SAFETY: on success `entry` points at one name the provider
            // allocated.
            let raw = unsafe { (*entry).pszName };
            // SAFETY: the provider's name is NUL-terminated and lives until
            // the buffer is freed, below.
            let name = (!raw.is_null()).then(|| unsafe { text(raw) });
            // SAFETY: `entry` came from the provider and is freed once.
            unsafe { NCryptFreeBuffer(entry.cast()) };
            if let Some(name) = name.filter(|name| name.starts_with(prefix)) {
                names.push(name);
            }
        };
        if !state.is_null() {
            // SAFETY: the enumeration state came from the provider.
            unsafe { NCryptFreeBuffer(state) };
        }
        outcome.map(|()| names)
    }

    /// Makes a key named `name`, never overwriting one.
    ///
    /// # Errors
    ///
    /// [`TpmError::Exists`], [`TpmError::Unsupported`], or the provider
    /// failing.
    pub fn make(&self, name: &str, algorithm: Algorithm) -> Result<Key, TpmError> {
        let (id, bits) = match algorithm {
            Algorithm::EcdsaP256 => (NCRYPT_ECDSA_P256_ALGORITHM, None),
            Algorithm::EcdsaP384 => (NCRYPT_ECDSA_P384_ALGORITHM, None),
            Algorithm::EcdsaP521 => (NCRYPT_ECDSA_P521_ALGORITHM, None),
            Algorithm::Rsa { bits } => (NCRYPT_RSA_ALGORITHM, Some(bits)),
        };
        // What the provider says of an algorithm or a length it does not
        // make: measured as these three for P-521 and RSA above 2048.
        let unsupported = |code| match code {
            NTE_NOT_SUPPORTED | NTE_INVALID_PARAMETER | E_INVALIDARG => TpmError::Unsupported,
            other => TpmError::Failed(other),
        };
        let name = wide(name);
        let mut key = Key(0);
        // SAFETY: the out pointer is valid; `id` is a static wide string and
        // `name` NUL-terminated; no flag asks to overwrite.
        let status = unsafe {
            NCryptCreatePersistedKey(
                self.0,
                &raw mut key.0,
                id,
                name.as_ptr(),
                CERT_KEY_SPEC::default(),
                0,
            )
        };
        checked(status, unsupported)?;
        if let Some(bits) = bits {
            let length = bits.to_le_bytes();
            // SAFETY: the key is one being made; `length` is four bytes.
            let status = unsafe {
                NCryptSetProperty(
                    key.0,
                    NCRYPT_LENGTH_PROPERTY,
                    length.as_ptr(),
                    4,
                    NCRYPT_SILENT_FLAG,
                )
            };
            checked(status, unsupported)?;
        }
        // SAFETY: the key is one being made, its properties set.
        let status = unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) };
        checked(status, unsupported)?;
        Ok(key)
    }

    /// Opens the key named `name`.
    ///
    /// # Errors
    ///
    /// [`TpmError::Missing`], or the provider failing.
    pub fn open(&self, name: &str) -> Result<Key, TpmError> {
        let name = wide(name);
        let mut key = Key(0);
        // SAFETY: the out pointer is valid; `name` is NUL-terminated.
        let status = unsafe {
            NCryptOpenKey(
                self.0,
                &raw mut key.0,
                name.as_ptr(),
                CERT_KEY_SPEC::default(),
                NCRYPT_SILENT_FLAG,
            )
        };
        checked(status, TpmError::Failed)?;
        Ok(key)
    }
}

/// A NUL-terminated wide string the system wrote, as text.
///
/// # Safety
///
/// `text` points at a NUL-terminated wide string that outlives the call.
unsafe fn text(text: *const u16) -> String {
    let mut length = 0;
    // SAFETY: the caller's guarantee: every unit up to the NUL is readable.
    while unsafe { text.wrapping_add(length).read() } != 0 {
        length += 1;
    }
    // SAFETY: the `length` units before the NUL were just read.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) })
}

fn take<'b>(bytes: &mut &'b [u8], count: usize) -> Option<&'b [u8]> {
    let (taken, rest) = bytes.split_at_checked(count)?;
    *bytes = rest;
    Some(taken)
}

fn word(bytes: &mut &[u8]) -> Option<u32> {
    take(bytes, 4)
        .and_then(|four| four.try_into().ok())
        .map(u32::from_le_bytes)
}

impl Key {
    /// What the provider holds of the key in `blob_type`'s form.
    fn export(&self, blob_type: windows_sys::core::PCWSTR) -> Result<Vec<u8>, TpmError> {
        let mut size = 0u32;
        // SAFETY: a null output asks for the size alone.
        let status = unsafe {
            NCryptExportKey(
                self.0,
                0,
                blob_type,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                &raw mut size,
                NCRYPT_SILENT_FLAG,
            )
        };
        checked(status, TpmError::Failed)?;
        let mut blob = vec![0u8; size as usize];
        // SAFETY: `blob` is `size` writable bytes.
        let status = unsafe {
            NCryptExportKey(
                self.0,
                0,
                blob_type,
                std::ptr::null(),
                blob.as_mut_ptr(),
                size,
                &raw mut size,
                NCRYPT_SILENT_FLAG,
            )
        };
        checked(status, TpmError::Failed)?;
        blob.truncate(size as usize);
        Ok(blob)
    }

    /// The key's public half.
    ///
    /// # Errors
    ///
    /// The provider failing, or giving a form not read here.
    pub fn public(&self) -> Result<Public, TpmError> {
        let unread = TpmError::Failed(NTE_NOT_SUPPORTED);
        if let Ok(blob) = self.export(BCRYPT_ECCPUBLIC_BLOB) {
            let mut rest = blob.as_slice();
            let magic = word(&mut rest).ok_or(unread)?;
            let length = word(&mut rest).ok_or(unread)? as usize;
            let curve = match magic {
                BCRYPT_ECDSA_PUBLIC_P256_MAGIC => 256,
                BCRYPT_ECDSA_PUBLIC_P384_MAGIC => 384,
                BCRYPT_ECDSA_PUBLIC_P521_MAGIC => 521,
                _ => return Err(unread),
            };
            debug_assert_eq!(size_of::<BCRYPT_ECCKEY_BLOB>(), 8);
            let x = take(&mut rest, length).ok_or(unread)?.to_vec();
            let y = take(&mut rest, length).ok_or(unread)?.to_vec();
            return Ok(Public::Ecdsa { curve, x, y });
        }
        let blob = self.export(BCRYPT_RSAPUBLIC_BLOB)?;
        let mut rest = blob.as_slice();
        debug_assert_eq!(size_of::<BCRYPT_RSAKEY_BLOB>(), 24);
        let magic = word(&mut rest).ok_or(unread)?;
        let _bits = word(&mut rest).ok_or(unread)?;
        let exponent = word(&mut rest).ok_or(unread)? as usize;
        let modulus = word(&mut rest).ok_or(unread)? as usize;
        take(&mut rest, 8).ok_or(unread)?;
        if magic != BCRYPT_RSAPUBLIC_MAGIC {
            return Err(unread);
        }
        Ok(Public::Rsa {
            exponent: take(&mut rest, exponent).ok_or(unread)?.to_vec(),
            modulus: take(&mut rest, modulus).ok_or(unread)?.to_vec(),
        })
    }

    /// Whether the provider would let the private half out in any form.
    ///
    /// # Errors
    ///
    /// The provider failing.
    pub fn exportable(&self) -> Result<bool, TpmError> {
        let mut policy = [0u8; 4];
        let mut size = 0u32;
        // SAFETY: `policy` is four writable bytes.
        let status = unsafe {
            NCryptGetProperty(
                self.0,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                policy.as_mut_ptr(),
                4,
                &raw mut size,
                NCRYPT_SILENT_FLAG,
            )
        };
        checked(status, TpmError::Failed)?;
        Ok(u32::from_le_bytes(policy) != 0)
    }

    /// Signs `digest`: an ECDSA key gives `r` then `s`, each the curve's
    /// length; an RSA key a PKCS #1 v1.5 signature naming the hash.
    ///
    /// # Errors
    ///
    /// The provider failing, as it does for a padding the key does not take.
    pub fn sign(&self, digest: &[u8], padding: Padding) -> Result<Vec<u8>, TpmError> {
        let named = BCRYPT_PKCS1_PADDING_INFO {
            pszAlgId: match padding {
                Padding::Pkcs1(Hash::Sha384) => BCRYPT_SHA384_ALGORITHM,
                Padding::Pkcs1(Hash::Sha512) => BCRYPT_SHA512_ALGORITHM,
                Padding::Pkcs1(Hash::Sha256) | Padding::None => BCRYPT_SHA256_ALGORITHM,
            },
        };
        let (info, flags): (*const core::ffi::c_void, u32) = match padding {
            Padding::Pkcs1(_) => (
                (&raw const named).cast(),
                NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG,
            ),
            Padding::None => (std::ptr::null(), NCRYPT_SILENT_FLAG),
        };
        let length = u32::try_from(digest.len()).map_err(|_| TpmError::Failed(E_INVALIDARG))?;
        let mut size = 0u32;
        // SAFETY: a null output asks for the size alone; `padding` outlives
        // the call.
        let status = unsafe {
            NCryptSignHash(
                self.0,
                info,
                digest.as_ptr(),
                length,
                std::ptr::null_mut(),
                0,
                &raw mut size,
                flags,
            )
        };
        checked(status, TpmError::Failed)?;
        let mut signature = vec![0u8; size as usize];
        // SAFETY: `signature` is `size` writable bytes; `padding` outlives
        // the call.
        let status = unsafe {
            NCryptSignHash(
                self.0,
                info,
                digest.as_ptr(),
                length,
                signature.as_mut_ptr(),
                size,
                &raw mut size,
                flags,
            )
        };
        checked(status, TpmError::Failed)?;
        signature.truncate(size as usize);
        Ok(signature)
    }

    /// Deletes the key from the TPM's store for good.
    ///
    /// # Errors
    ///
    /// The provider failing; the key is then still there.
    pub fn delete(mut self) -> Result<(), TpmError> {
        // The Platform Crypto Provider refuses the silent flag here
        // (`NTE_BAD_FLAGS`, measured); deleting raises no window either way.
        // SAFETY: the handle is this value's; on success the provider frees
        // it, so it is forgotten here and never freed again.
        let status = unsafe { NCryptDeleteKey(self.0, 0) };
        if status == 0 {
            self.0 = 0;
        }
        checked(status, TpmError::Failed)
    }
}

/// `data`'s digest under `hash`.
///
/// # Errors
///
/// [`TpmError::Failed`] for more than four gigabytes, or the system failing.
pub fn digest(hash: Hash, data: &[u8]) -> Result<Vec<u8>, TpmError> {
    let (algorithm, length) = match hash {
        Hash::Sha256 => (BCRYPT_SHA256_ALG_HANDLE, 32u32),
        Hash::Sha384 => (BCRYPT_SHA384_ALG_HANDLE, 48),
        Hash::Sha512 => (BCRYPT_SHA512_ALG_HANDLE, 64),
    };
    let input = u32::try_from(data.len()).map_err(|_| TpmError::Failed(E_INVALIDARG))?;
    let mut out = vec![0u8; length as usize];
    // SAFETY: the pseudo-handle names a built-in algorithm; `data` is
    // `input` readable bytes and `out` the digest's length.
    let status = unsafe {
        BCryptHash(
            algorithm,
            std::ptr::null(),
            0,
            data.as_ptr(),
            input,
            out.as_mut_ptr(),
            length,
        )
    };
    if status != 0 {
        return Err(TpmError::Failed(status));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, reason = "tests")]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    /// A name of this run's own, so no key a person made is ever opened.
    fn named(what: &str) -> String {
        format!("hedwig-win-test-{}-{what}", std::process::id())
    }

    /// Deletes the run's key of this name when dropped, should a test stop
    /// before deleting it itself.
    struct Cleared(String);

    impl Drop for Cleared {
        fn drop(&mut self) {
            if let Ok(key) = Provider::platform().and_then(|provider| provider.open(&self.0)) {
                let _ = key.delete();
            }
        }
    }

    /// FIPS 180-4's example "abc", under each hash.
    #[test]
    fn digests_are_fips_180_s_known_answers() {
        let hex = |bytes: Vec<u8>| -> String {
            bytes.iter().fold(String::new(), |mut out, byte| {
                let _ = write!(out, "{byte:02x}");
                out
            })
        };
        assert_eq!(
            hex(digest(Hash::Sha256, b"abc").expect("a digest")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(digest(Hash::Sha384, b"abc").expect("a digest")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex(digest(Hash::Sha512, b"abc").expect("a digest")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    /// Each kind this TPM makes is made under its name, never exportable,
    /// read for its public half, listed under its prefix, opened by name,
    /// signs a digest, and is gone once deleted.
    #[test]
    fn a_key_is_made_read_listed_signed_and_deleted() {
        let provider = Provider::platform().expect("this workstation's TPM");
        let prefix = named("kinds-");
        for (what, algorithm, padding, length) in [
            ("p256", Algorithm::EcdsaP256, Padding::None, 64),
            ("p384", Algorithm::EcdsaP384, Padding::None, 96),
            (
                "rsa",
                Algorithm::Rsa { bits: 2048 },
                Padding::Pkcs1(Hash::Sha512),
                256,
            ),
        ] {
            let name = format!("{prefix}{what}");
            let _cleared = Cleared(name.clone());
            let key = provider.make(&name, algorithm).expect("made");
            assert!(!key.exportable().expect("its policy"));
            let public = key.public().expect("its public half");
            match (algorithm, &public) {
                (Algorithm::EcdsaP256, Public::Ecdsa { curve: 256, x, y })
                | (Algorithm::EcdsaP384, Public::Ecdsa { curve: 384, x, y }) => {
                    assert_eq!(x.len(), y.len());
                }
                (Algorithm::Rsa { bits: 2048 }, Public::Rsa { modulus, exponent }) => {
                    assert_eq!(modulus.len(), 256);
                    assert_eq!(exponent, &[1, 0, 1]);
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(provider.names(&prefix).expect("listed"), vec![name.clone()]);
            let reopened = provider.open(&name).expect("opened by name");
            assert_eq!(reopened.public().expect("the same half"), public);
            let hash = match padding {
                Padding::Pkcs1(hash) => hash,
                Padding::None if length == 96 => Hash::Sha384,
                Padding::None => Hash::Sha256,
            };
            let signature = reopened
                .sign(&digest(hash, b"hedwig").expect("a digest"), padding)
                .expect("signed");
            assert_eq!(signature.len(), length);
            drop(key);
            reopened.delete().expect("deleted");
            assert!(matches!(provider.open(&name), Err(TpmError::Missing)));
            assert_eq!(
                provider.names(&prefix).expect("listed"),
                Vec::<String>::new()
            );
        }
    }

    /// A name is never made twice, and the first key stays as it was; a
    /// padding the key does not take fails rather than signing.
    #[test]
    fn a_name_is_never_overwritten_and_a_wrong_padding_signs_nothing() {
        let provider = Provider::platform().expect("this workstation's TPM");
        let name = named("twice");
        let _cleared = Cleared(name.clone());
        let first = provider
            .make(&name, Algorithm::EcdsaP256)
            .expect("made once");
        let public = first.public().expect("its half");
        assert_eq!(
            provider.make(&name, Algorithm::EcdsaP256).map(drop),
            Err(TpmError::Exists)
        );
        assert_eq!(
            provider.open(&name).expect("still there").public(),
            Ok(public)
        );
        let refused = first.sign(
            &digest(Hash::Sha256, b"hedwig").expect("a digest"),
            Padding::Pkcs1(Hash::Sha256),
        );
        assert!(matches!(refused, Err(TpmError::Failed(_))), "{refused:?}");
        first.delete().expect("deleted");
    }

    /// What this TPM does not make is said as such; where another TPM makes
    /// it, it is made and deleted like any key.
    #[test]
    fn a_kind_the_tpm_does_not_make_is_unsupported() {
        let provider = Provider::platform().expect("this workstation's TPM");
        for (what, algorithm) in [
            ("p521", Algorithm::EcdsaP521),
            ("rsa4096", Algorithm::Rsa { bits: 4096 }),
        ] {
            let _cleared = Cleared(named(what));
            match provider.make(&named(what), algorithm) {
                Ok(key) => key.delete().expect("deleted"),
                Err(TpmError::Unsupported) => println!("{what}: not made by this TPM"),
                Err(other) => panic!("{what}: {other}"),
            }
        }
    }

    /// A provider that is not registered does not open.
    #[test]
    fn a_provider_not_there_is_unavailable() {
        assert!(matches!(
            Provider::named("hedwig no such provider"),
            Err(TpmError::Unavailable(_))
        ));
        assert!(
            TpmError::Unavailable(-2_146_893_794)
                .to_string()
                .starts_with("the TPM's provider would not open (0x8009001e")
        );
    }
}
