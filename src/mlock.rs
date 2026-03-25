//! Best-effort memory locking to prevent sensitive data from being swapped to disk.
//!
//! Failures are silently ignored — mlock may fail due to insufficient privileges
//! or resource limits (e.g., RLIMIT_MEMLOCK on Linux). The data is still usable,
//! just not swap-protected.

/// Lock a region of memory to prevent it from being swapped to disk.
/// Returns true if successful, false otherwise. Failure is non-fatal.
pub fn mlock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    #[cfg(unix)]
    {
        unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
    }
    #[cfg(windows)]
    {
        unsafe {
            windows_sys::Win32::System::Memory::VirtualLock(ptr as *mut core::ffi::c_void, len) != 0
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        false
    }
}

/// Unlock a previously locked memory region.
pub fn munlock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    #[cfg(unix)]
    {
        unsafe { libc::munlock(ptr as *const libc::c_void, len) == 0 }
    }
    #[cfg(windows)]
    {
        unsafe {
            windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *mut core::ffi::c_void, len)
                != 0
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ptr, len);
        false
    }
}

/// Lock a value's memory region. Returns true if successful.
pub fn mlock_value<T>(value: &T) -> bool {
    mlock(value as *const T as *const u8, std::mem::size_of::<T>())
}

/// Unlock a value's memory region.
pub fn munlock_value<T>(value: &T) -> bool {
    munlock(value as *const T as *const u8, std::mem::size_of::<T>())
}
