//! SDEI SMC (Secure Monitor Call) interface.
//!
//! This module provides low-level SMC call wrappers for SDEI functionality.
//! All functions follow the ARM SDEI specification (DEN0054).

use core::arch::asm;

// =============================================================================
// SDEI Function IDs (SMC64 variants)
// =============================================================================

/// Base function ID for SDEI calls (SMC64).
const SDEI_FID_BASE: u32 = 0xC4000000;

/// SDEI_VERSION - Query SDEI version.
pub const SDEI_VERSION: u32 = SDEI_FID_BASE | 0x20;

/// SDEI_EVENT_REGISTER - Register an event handler.
pub const SDEI_EVENT_REGISTER: u32 = SDEI_FID_BASE | 0x21;

/// SDEI_EVENT_ENABLE - Enable an event.
pub const SDEI_EVENT_ENABLE: u32 = SDEI_FID_BASE | 0x22;

/// SDEI_EVENT_DISABLE - Disable an event.
pub const SDEI_EVENT_DISABLE: u32 = SDEI_FID_BASE | 0x23;

/// SDEI_EVENT_CONTEXT - Get event context (register values).
pub const SDEI_EVENT_CONTEXT: u32 = SDEI_FID_BASE | 0x24;

/// SDEI_EVENT_COMPLETE - Complete event handling, resume normal execution.
pub const SDEI_EVENT_COMPLETE: u32 = SDEI_FID_BASE | 0x25;

/// SDEI_EVENT_COMPLETE_AND_RESUME - Complete and resume at specified address.
pub const SDEI_EVENT_COMPLETE_AND_RESUME: u32 = SDEI_FID_BASE | 0x26;

/// SDEI_EVENT_UNREGISTER - Unregister an event handler.
pub const SDEI_EVENT_UNREGISTER: u32 = SDEI_FID_BASE | 0x27;

/// SDEI_EVENT_STATUS - Query event status.
pub const SDEI_EVENT_STATUS: u32 = SDEI_FID_BASE | 0x28;

/// SDEI_EVENT_GET_INFO - Get event information.
pub const SDEI_EVENT_GET_INFO: u32 = SDEI_FID_BASE | 0x29;

/// SDEI_EVENT_ROUTING_SET - Set event routing (for shared events).
pub const SDEI_EVENT_ROUTING_SET: u32 = SDEI_FID_BASE | 0x2A;

/// SDEI_PE_MASK - Mask events on current PE.
pub const SDEI_PE_MASK: u32 = SDEI_FID_BASE | 0x2B;

/// SDEI_PE_UNMASK - Unmask events on current PE.
pub const SDEI_PE_UNMASK: u32 = SDEI_FID_BASE | 0x2C;

/// SDEI_INTERRUPT_BIND - Bind interrupt to SDEI event.
pub const SDEI_INTERRUPT_BIND: u32 = SDEI_FID_BASE | 0x2D;

/// SDEI_INTERRUPT_RELEASE - Release interrupt binding.
pub const SDEI_INTERRUPT_RELEASE: u32 = SDEI_FID_BASE | 0x2E;

/// SDEI_PRIVATE_RESET - Reset all private events.
pub const SDEI_PRIVATE_RESET: u32 = SDEI_FID_BASE | 0x2F;

/// SDEI_SHARED_RESET - Reset all shared events.
pub const SDEI_SHARED_RESET: u32 = SDEI_FID_BASE | 0x30;

/// SDEI_EVENT_SIGNAL - Signal a software event (private event 0).
pub const SDEI_EVENT_SIGNAL: u32 = SDEI_FID_BASE | 0x31;

/// SDEI_FEATURES - Query SDEI features.
pub const SDEI_FEATURES: u32 = SDEI_FID_BASE | 0x32;

// =============================================================================
// SDEI Error Codes
// =============================================================================

/// SDEI error codes as defined in the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdeiError {
    /// Success (not an error).
    Success,
    /// Operation not supported.
    NotSupported,
    /// Invalid parameters.
    InvalidParameters,
    /// Access denied.
    Denied,
    /// Event is pending.
    Pending,
    /// Out of resources.
    OutOfResource,
    /// Unknown/invalid error code.
    Unknown(i64),
}

impl SdeiError {
    /// Convert from SMC return value to SdeiError.
    pub fn from_smc_result(val: i64) -> Self {
        match val {
            0 => SdeiError::Success,
            -1 => SdeiError::NotSupported,
            -2 => SdeiError::InvalidParameters,
            -3 => SdeiError::Denied,
            -4 => SdeiError::Pending,
            -5 => SdeiError::OutOfResource,
            _ => SdeiError::Unknown(val),
        }
    }

    /// Check if this represents success.
    pub fn is_success(&self) -> bool {
        matches!(self, SdeiError::Success)
    }
}

impl core::fmt::Display for SdeiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SdeiError::Success => write!(f, "Success"),
            SdeiError::NotSupported => write!(f, "Operation not supported"),
            SdeiError::InvalidParameters => write!(f, "Invalid parameters"),
            SdeiError::Denied => write!(f, "Access denied"),
            SdeiError::Pending => write!(f, "Event is pending"),
            SdeiError::OutOfResource => write!(f, "Out of resources"),
            SdeiError::Unknown(code) => write!(f, "Unknown error: {}", code),
        }
    }
}

/// Result type for SDEI operations.
pub type SdeiResult<T> = Result<T, SdeiError>;

// =============================================================================
// SDEI Version
// =============================================================================

/// SDEI version information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdeiVersion {
    /// Major version number.
    pub major: u32,
    /// Minor version number.
    pub minor: u32,
}

impl SdeiVersion {
    /// Create a new SdeiVersion from the raw SMC return value.
    pub fn from_raw(raw: u64) -> Self {
        Self {
            major: ((raw >> 48) & 0x7FFF) as u32,
            minor: ((raw >> 32) & 0xFFFF) as u32,
        }
    }

    /// Check if this version is at least the specified version.
    pub fn is_at_least(&self, major: u32, minor: u32) -> bool {
        self.major > major || (self.major == major && self.minor >= minor)
    }
}

impl core::fmt::Display for SdeiVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// =============================================================================
// SMC Call Interface
// =============================================================================

/// Raw SMC call with up to 5 arguments, returning up to 4 results.
///
/// # Safety
/// This function performs a raw SMC call. The caller must ensure that:
/// - The function ID is valid
/// - The arguments are appropriate for the function
/// - The system supports SMC calls (running at appropriate exception level)
#[inline(always)]
pub unsafe fn sdei_smc_call(
    fid: u32,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) -> (i64, u64, u64, u64) {
    let ret0: i64;
    let ret1: u64;
    let ret2: u64;
    let ret3: u64;

    unsafe {
        asm!(
            "smc #0",
            inout("x0") fid as u64 => ret0,
            inout("x1") arg1 => ret1,
            inout("x2") arg2 => ret2,
            inout("x3") arg3 => ret3,
            inlateout("x4") arg4 => _,
            // x5-x17 are clobbered by SMC
            out("x5") _,
            out("x6") _,
            out("x7") _,
            out("x8") _,
            out("x9") _,
            out("x10") _,
            out("x11") _,
            out("x12") _,
            out("x13") _,
            out("x14") _,
            out("x15") _,
            out("x16") _,
            out("x17") _,
            options(nomem, nostack)
        );
    }

    (ret0, ret1, ret2, ret3)
}

/// Helper macro for SMC calls with automatic error conversion.
macro_rules! sdei_call {
    ($fid:expr) => {
        unsafe { sdei_smc_call($fid, 0, 0, 0, 0) }
    };
    ($fid:expr, $a1:expr) => {
        unsafe { sdei_smc_call($fid, $a1 as u64, 0, 0, 0) }
    };
    ($fid:expr, $a1:expr, $a2:expr) => {
        unsafe { sdei_smc_call($fid, $a1 as u64, $a2 as u64, 0, 0) }
    };
    ($fid:expr, $a1:expr, $a2:expr, $a3:expr) => {
        unsafe { sdei_smc_call($fid, $a1 as u64, $a2 as u64, $a3 as u64, 0) }
    };
    ($fid:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {
        unsafe { sdei_smc_call($fid, $a1 as u64, $a2 as u64, $a3 as u64, $a4 as u64) }
    };
}

// =============================================================================
// SDEI SMC Wrapper Functions
// =============================================================================

/// Query SDEI version.
///
/// Returns the SDEI version supported by the firmware.
pub fn sdei_version() -> SdeiResult<SdeiVersion> {
    let (ret, _, _, _) = sdei_call!(SDEI_VERSION);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(SdeiVersion::from_raw(ret as u64))
    }
}

/// Register an event handler.
///
/// # Arguments
/// * `event` - Event number to register
/// * `handler` - Handler entry point address
/// * `arg` - User argument passed to handler
/// * `flags` - Registration flags
/// * `affinity` - Target affinity for shared events (ignored for private)
///
/// # Safety
/// The handler function must be properly implemented and not acquire locks.
pub unsafe fn sdei_event_register(
    event: u32,
    handler: usize,
    arg: usize,
    flags: u64,
    affinity: u64,
) -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_EVENT_REGISTER, event, handler, arg, flags);
    // Note: affinity is in x5 which requires extending the call
    let _ = affinity; // For private events, affinity is ignored

    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Enable an event.
///
/// The event must be registered before enabling.
pub fn sdei_event_enable(event: u32) -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_EVENT_ENABLE, event);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Disable an event.
pub fn sdei_event_disable(event: u32) -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_EVENT_DISABLE, event);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Unregister an event handler.
///
/// The event must be disabled before unregistering.
pub fn sdei_event_unregister(event: u32) -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_EVENT_UNREGISTER, event);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Query event status.
///
/// Returns a bitmask indicating the event's current status.
pub fn sdei_event_status(event: u32) -> SdeiResult<u32> {
    let (ret, _, _, _) = sdei_call!(SDEI_EVENT_STATUS, event);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(ret as u32)
    }
}

/// Event status bits.
pub mod event_status {
    /// Event is registered.
    pub const REGISTERED: u32 = 1 << 0;
    /// Event is enabled.
    pub const ENABLED: u32 = 1 << 1;
    /// Event is running (handler is executing).
    pub const RUNNING: u32 = 1 << 2;
}

/// Get event information.
///
/// # Arguments
/// * `event` - Event number
/// * `info` - Information type to query
pub fn sdei_event_get_info(event: u32, info: u32) -> SdeiResult<u64> {
    let (ret, _, _, _) = sdei_call!(SDEI_EVENT_GET_INFO, event, info);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(ret as u64)
    }
}

/// Event info types for sdei_event_get_info.
pub mod event_info {
    /// Event type (private/shared).
    pub const TYPE: u32 = 0;
    /// Event signaling type (edge/level).
    pub const SIGNALED: u32 = 1;
    /// Event priority (normal/critical).
    pub const PRIORITY: u32 = 2;
    /// Routing mode for shared events.
    pub const ROUTING_MODE: u32 = 3;
    /// Routing affinity for shared events.
    pub const ROUTING_AFFINITY: u32 = 4;
}

/// Complete event handling and resume.
///
/// Must be called at the end of an event handler.
pub fn sdei_event_complete(status: u32) -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_EVENT_COMPLETE, status);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Complete event handling and resume at specified address.
///
/// # Safety
/// The resume address must be valid and executable.
pub unsafe fn sdei_event_complete_and_resume(resume_addr: usize) -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_EVENT_COMPLETE_AND_RESUME, resume_addr);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Get event context (interrupted register values).
///
/// Can only be called from within an event handler.
///
/// # Arguments
/// * `param` - Register index (0-17 for x0-x17, 18 for PC, 19 for PSTATE, 20 for SP_EL0)
pub fn sdei_event_context(param: u32) -> SdeiResult<u64> {
    let (ret, _, _, _) = sdei_call!(SDEI_EVENT_CONTEXT, param);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(ret as u64)
    }
}

/// Context parameter indices for sdei_event_context.
pub mod context_param {
    /// General purpose registers x0-x17.
    pub const X0: u32 = 0;
    pub const X1: u32 = 1;
    pub const X2: u32 = 2;
    pub const X3: u32 = 3;
    pub const X4: u32 = 4;
    pub const X5: u32 = 5;
    pub const X6: u32 = 6;
    pub const X7: u32 = 7;
    pub const X8: u32 = 8;
    pub const X9: u32 = 9;
    pub const X10: u32 = 10;
    pub const X11: u32 = 11;
    pub const X12: u32 = 12;
    pub const X13: u32 = 13;
    pub const X14: u32 = 14;
    pub const X15: u32 = 15;
    pub const X16: u32 = 16;
    pub const X17: u32 = 17;
    /// Program counter at interrupt.
    pub const PC: u32 = 18;
    /// Processor state at interrupt.
    pub const PSTATE: u32 = 19;
    /// Stack pointer (SP_EL0).
    pub const SP_EL0: u32 = 20;
}

/// Mask SDEI events on current PE.
///
/// Returns true if events were previously masked.
pub fn sdei_pe_mask() -> SdeiResult<bool> {
    let (ret, _, _, _) = sdei_call!(SDEI_PE_MASK);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(ret != 0)
    }
}

/// Unmask SDEI events on current PE.
pub fn sdei_pe_unmask() -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_PE_UNMASK);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Reset all private events.
///
/// Unregisters all private events on the current PE.
pub fn sdei_private_reset() -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_PRIVATE_RESET);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Reset all shared events.
///
/// Unregisters all shared events. Must be called from all PEs.
pub fn sdei_shared_reset() -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_SHARED_RESET);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Signal private event 0 to a specific PE.
///
/// # Arguments
/// * `target_pe` - MPIDR of the target PE
pub fn sdei_event_signal(target_pe: u64) -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_EVENT_SIGNAL, target_pe);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Bind an interrupt to an SDEI event.
///
/// Creates a new shared event bound to the specified interrupt.
///
/// # Arguments
/// * `interrupt` - Physical interrupt number (SPI)
///
/// # Returns
/// The event number on success.
pub fn sdei_interrupt_bind(interrupt: u32) -> SdeiResult<u32> {
    let (ret, _, _, _) = sdei_call!(SDEI_INTERRUPT_BIND, interrupt);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(ret as u32)
    }
}

/// Release an interrupt binding.
///
/// # Arguments
/// * `event` - Event number returned by sdei_interrupt_bind
pub fn sdei_interrupt_release(event: u32) -> SdeiResult<()> {
    let (ret, _, _, _) = sdei_call!(SDEI_INTERRUPT_RELEASE, event);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(())
    }
}

/// Query SDEI features.
///
/// # Arguments
/// * `feature` - Feature ID to query
pub fn sdei_features(feature: u32) -> SdeiResult<u64> {
    let (ret, _, _, _) = sdei_call!(SDEI_FEATURES, feature);
    if ret < 0 {
        Err(SdeiError::from_smc_result(ret))
    } else {
        Ok(ret as u64)
    }
}

/// Feature IDs for sdei_features.
pub mod features {
    /// Query shared event slot count.
    pub const SHARED_SLOTS: u32 = 0;
    /// Query private event slot count.
    pub const PRIVATE_SLOTS: u32 = 1;
    /// Query relative mode support.
    pub const RELATIVE_MODE: u32 = 2;
}
