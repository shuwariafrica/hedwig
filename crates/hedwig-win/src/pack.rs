//! Windows' own compression, LZMS, through the Compression API in
//! `cabinet.dll`: what setup's payload is carried in, with nothing of a
//! compressor's own shipped beside it.

use std::io;

use windows_sys::Win32::Storage::Compression::{
    COMPRESS_ALGORITHM_LZMS, CloseCompressor, CloseDecompressor, Compress, CreateCompressor,
    CreateDecompressor, Decompress,
};

/// `bytes`, compressed in one LZMS stream.
///
/// # Errors
///
/// What the system said.
pub fn compress(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut compressor = std::ptr::null_mut();
    // SAFETY: the out parameter is valid; no allocation routines are given.
    if unsafe {
        CreateCompressor(
            COMPRESS_ALGORITHM_LZMS,
            std::ptr::null(),
            &raw mut compressor,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut out = vec![0u8; bytes.len() + 65_536];
    let mut size = 0usize;
    // SAFETY: both buffers are valid for the lengths given.
    let done = unsafe {
        Compress(
            compressor,
            bytes.as_ptr().cast(),
            bytes.len(),
            out.as_mut_ptr().cast(),
            out.len(),
            &raw mut size,
        )
    };
    let failed = (done == 0).then(io::Error::last_os_error);
    // SAFETY: made above and closed once.
    unsafe { CloseCompressor(compressor) };
    if let Some(error) = failed {
        return Err(error);
    }
    out.truncate(size);
    Ok(out)
}

/// The `length` bytes an LZMS stream holds.
///
/// # Errors
///
/// What the system said: the stream is not one, or holds another length.
pub fn decompress(stream: &[u8], length: usize) -> io::Result<Vec<u8>> {
    let mut decompressor = std::ptr::null_mut();
    // SAFETY: the out parameter is valid; no allocation routines are given.
    if unsafe {
        CreateDecompressor(
            COMPRESS_ALGORITHM_LZMS,
            std::ptr::null(),
            &raw mut decompressor,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut out = vec![0u8; length];
    let mut size = 0usize;
    // SAFETY: both buffers are valid for the lengths given.
    let done = unsafe {
        Decompress(
            decompressor,
            stream.as_ptr().cast(),
            stream.len(),
            out.as_mut_ptr().cast(),
            out.len(),
            &raw mut size,
        )
    };
    let failed = (done == 0).then(io::Error::last_os_error);
    // SAFETY: made above and closed once.
    unsafe { CloseDecompressor(decompressor) };
    if let Some(error) = failed {
        return Err(error);
    }
    if size != length {
        return Err(io::Error::from_raw_os_error(13));
    }
    Ok(out)
}
