//! Safe wrapper around `rte_eal_init`.

use std::ffi::CString;
use std::os::raw::c_char;

use super::ffi;

#[derive(Debug)]
pub struct EalInitError {
    pub rc: i32,
}

impl std::fmt::Display for EalInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rte_eal_init failed with rc={}", self.rc)
    }
}
impl std::error::Error for EalInitError {}

/// Initializes the DPDK Environment Abstraction Layer from the given
/// EAL command-line arguments (e.g. `["tcp", "-l", "0-1", "-n", "4"]`).
///
/// Must be called exactly once, before any other DPDK call, and only ever
/// from the process's main thread. Consumes the leading EAL-owned argv
/// tokens the way `rte_eal_init` normally does; the return value is how
/// many argv entries EAL consumed, mirroring the C API.
pub fn init(args: &[&str]) -> Result<i32, EalInitError> {
    let c_args: Vec<CString> = args
        .iter()
        .map(|s| CString::new(*s).expect("EAL argument contained a NUL byte"))
        .collect();
    let mut argv_ptrs: Vec<*mut c_char> =
        c_args.iter().map(|s| s.as_ptr() as *mut c_char).collect();

    // SAFETY: argv_ptrs is a valid, NUL-terminated-per-entry array of argc
    // pointers kept alive for the duration of the call; rte_eal_init does
    // not retain the pointers past this call (it copies what it needs).
    let rc = unsafe { ffi::rte_eal_init(argv_ptrs.len() as i32, argv_ptrs.as_mut_ptr()) };
    if rc < 0 {
        return Err(EalInitError { rc });
    }
    Ok(rc)
}
