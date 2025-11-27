//! SDEI Event management high-level interface.
//!
//! This module provides a safer, more ergonomic interface for managing SDEI events.

use crate::smc::{self, SdeiError, SdeiResult, SdeiVersion, event_info, event_status, features};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// SDEI event registration flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdeiEventFlags(u64);

impl SdeiEventFlags {
    /// No special flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Use relative mode for routing (if supported).
    pub const fn relative() -> Self {
        Self(1 << 0)
    }

    /// Get the raw flag value.
    pub const fn bits(&self) -> u64 {
        self.0
    }
}

/// SDEI event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdeiEventType {
    /// Private event - per-CPU, like PPIs.
    Private,
    /// Shared event - can be routed to any PE, like SPIs.
    Shared,
}

/// SDEI event priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdeiEventPriority {
    /// Normal priority - can be masked by SDEI_PE_MASK.
    Normal,
    /// Critical priority - cannot be masked, true NMI behavior.
    Critical,
}

/// Information about an SDEI event.
#[derive(Debug, Clone, Copy)]
pub struct SdeiEventInfo {
    /// Event number.
    pub event: u32,
    /// Event type.
    pub event_type: SdeiEventType,
    /// Event priority.
    pub priority: SdeiEventPriority,
    /// Whether the event is currently registered.
    pub registered: bool,
    /// Whether the event is currently enabled.
    pub enabled: bool,
    /// Whether the event handler is currently running.
    pub running: bool,
}

/// Main SDEI interface structure.
///
/// Provides methods for initializing SDEI and managing events.
pub struct Sdei {
    /// SDEI version, populated after init.
    version: AtomicU32,
    /// Whether SDEI has been initialized.
    initialized: AtomicBool,
    /// Number of private event slots.
    private_slots: AtomicU32,
    /// Number of shared event slots.
    shared_slots: AtomicU32,
}

impl Sdei {
    /// Create a new SDEI interface instance.
    pub const fn new() -> Self {
        Self {
            version: AtomicU32::new(0),
            initialized: AtomicBool::new(false),
            private_slots: AtomicU32::new(0),
            shared_slots: AtomicU32::new(0),
        }
    }

    /// Initialize SDEI interface.
    ///
    /// This must be called before any other SDEI operations.
    /// It queries the firmware for SDEI version and capabilities.
    pub fn init(&self) -> SdeiResult<SdeiVersion> {
        // Query SDEI version
        let version = smc::sdei_version()?;

        // Check minimum version (1.0)
        if !version.is_at_least(1, 0) {
            return Err(SdeiError::NotSupported);
        }

        // Store version
        let version_packed = ((version.major as u32) << 16) | (version.minor as u32);
        self.version.store(version_packed, Ordering::Release);

        // Query slot counts
        if let Ok(private) = smc::sdei_features(features::PRIVATE_SLOTS) {
            self.private_slots.store(private as u32, Ordering::Release);
        }
        if let Ok(shared) = smc::sdei_features(features::SHARED_SLOTS) {
            self.shared_slots.store(shared as u32, Ordering::Release);
        }

        self.initialized.store(true, Ordering::Release);

        #[cfg(feature = "log")]
        log::info!(
            "SDEI initialized: version {}, {} private slots, {} shared slots",
            version,
            self.private_slots.load(Ordering::Relaxed),
            self.shared_slots.load(Ordering::Relaxed)
        );

        Ok(version)
    }

    /// Check if SDEI is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Get the SDEI version.
    pub fn version(&self) -> Option<SdeiVersion> {
        if !self.is_initialized() {
            return None;
        }
        let packed = self.version.load(Ordering::Acquire);
        Some(SdeiVersion {
            major: (packed >> 16) as u32,
            minor: (packed & 0xFFFF) as u32,
        })
    }

    /// Register an event handler.
    ///
    /// # Arguments
    /// * `event` - Event number to register
    /// * `handler` - Handler entry point address
    /// * `arg` - User argument passed to handler in x1
    /// * `flags` - Registration flags
    /// * `affinity` - Target MPIDR for shared events (ignored for private)
    ///
    /// # Safety
    /// The caller must ensure:
    /// - The handler is a valid function that follows SDEI handler conventions
    /// - The handler does not acquire any locks
    /// - The handler calls sdei_event_complete() or sdei_event_complete_and_resume()
    pub unsafe fn event_register(
        &self,
        event: u32,
        handler: usize,
        arg: usize,
        flags: SdeiEventFlags,
        affinity: u64,
    ) -> SdeiResult<()> {
        if !self.is_initialized() {
            return Err(SdeiError::NotSupported);
        }
        unsafe { smc::sdei_event_register(event, handler, arg, flags.bits(), affinity) }
    }

    /// Register a private event handler (convenience method).
    ///
    /// # Safety
    /// Same requirements as `event_register`.
    pub unsafe fn register_private_event(
        &self,
        event: u32,
        handler: usize,
        arg: usize,
    ) -> SdeiResult<()> {
        unsafe { self.event_register(event, handler, arg, SdeiEventFlags::empty(), 0) }
    }

    /// Unregister an event handler.
    ///
    /// The event must be disabled before unregistering.
    pub fn event_unregister(&self, event: u32) -> SdeiResult<()> {
        if !self.is_initialized() {
            return Err(SdeiError::NotSupported);
        }
        smc::sdei_event_unregister(event)
    }

    /// Enable an event.
    pub fn event_enable(&self, event: u32) -> SdeiResult<()> {
        if !self.is_initialized() {
            return Err(SdeiError::NotSupported);
        }
        smc::sdei_event_enable(event)
    }

    /// Disable an event.
    pub fn event_disable(&self, event: u32) -> SdeiResult<()> {
        if !self.is_initialized() {
            return Err(SdeiError::NotSupported);
        }
        smc::sdei_event_disable(event)
    }

    /// Get event information.
    pub fn event_info(&self, event: u32) -> SdeiResult<SdeiEventInfo> {
        if !self.is_initialized() {
            return Err(SdeiError::NotSupported);
        }

        // Get event type
        let type_val = smc::sdei_event_get_info(event, event_info::TYPE)?;
        let event_type = if type_val == 0 {
            SdeiEventType::Shared
        } else {
            SdeiEventType::Private
        };

        // Get priority
        let prio_val = smc::sdei_event_get_info(event, event_info::PRIORITY)?;
        let priority = if prio_val == 0 {
            SdeiEventPriority::Normal
        } else {
            SdeiEventPriority::Critical
        };

        // Get status
        let status = smc::sdei_event_status(event)?;
        let registered = (status & event_status::REGISTERED) != 0;
        let enabled = (status & event_status::ENABLED) != 0;
        let running = (status & event_status::RUNNING) != 0;

        Ok(SdeiEventInfo {
            event,
            event_type,
            priority,
            registered,
            enabled,
            running,
        })
    }

    /// Mask all SDEI events on the current PE.
    ///
    /// Returns true if events were already masked.
    pub fn pe_mask(&self) -> SdeiResult<bool> {
        smc::sdei_pe_mask()
    }

    /// Unmask SDEI events on the current PE.
    pub fn pe_unmask(&self) -> SdeiResult<()> {
        smc::sdei_pe_unmask()
    }

    /// Signal private event 0 to a target PE.
    ///
    /// This is the software-triggered NMI mechanism.
    ///
    /// # Arguments
    /// * `target_mpidr` - MPIDR of the target PE
    pub fn signal_event(&self, target_mpidr: u64) -> SdeiResult<()> {
        if !self.is_initialized() {
            return Err(SdeiError::NotSupported);
        }
        smc::sdei_event_signal(target_mpidr)
    }

    /// Bind an interrupt to create a new SDEI event.
    ///
    /// # Arguments
    /// * `interrupt` - SPI number to bind
    ///
    /// # Returns
    /// The event number for the bound interrupt.
    pub fn bind_interrupt(&self, interrupt: u32) -> SdeiResult<u32> {
        if !self.is_initialized() {
            return Err(SdeiError::NotSupported);
        }
        smc::sdei_interrupt_bind(interrupt)
    }

    /// Release an interrupt binding.
    pub fn release_interrupt(&self, event: u32) -> SdeiResult<()> {
        if !self.is_initialized() {
            return Err(SdeiError::NotSupported);
        }
        smc::sdei_interrupt_release(event)
    }

    /// Reset all private events on current PE.
    pub fn private_reset(&self) -> SdeiResult<()> {
        smc::sdei_private_reset()
    }

    /// Reset all shared events.
    pub fn shared_reset(&self) -> SdeiResult<()> {
        smc::sdei_shared_reset()
    }
}

impl Default for Sdei {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Event Handler Helpers (to be called from within handlers)
// =============================================================================

/// Complete the current event and resume normal execution.
///
/// This must be called at the end of every SDEI event handler.
///
/// # Arguments
/// * `status` - Completion status (typically 0 for success)
#[inline]
pub fn event_complete(status: u32) -> SdeiResult<()> {
    smc::sdei_event_complete(status)
}

/// Complete the current event and resume at a different address.
///
/// # Safety
/// The resume address must be valid and executable.
#[inline]
pub unsafe fn event_complete_and_resume(resume_addr: usize) -> SdeiResult<()> {
    unsafe { smc::sdei_event_complete_and_resume(resume_addr) }
}

/// Get the interrupted PC (program counter) from event context.
#[inline]
pub fn get_interrupted_pc() -> SdeiResult<usize> {
    smc::sdei_event_context(smc::context_param::PC).map(|v| v as usize)
}

/// Get the interrupted SP (stack pointer) from event context.
#[inline]
pub fn get_interrupted_sp() -> SdeiResult<usize> {
    smc::sdei_event_context(smc::context_param::SP_EL0).map(|v| v as usize)
}

/// Get a general purpose register from event context.
///
/// # Arguments
/// * `reg` - Register index (0-17 for x0-x17)
#[inline]
pub fn get_interrupted_gpr(reg: u32) -> SdeiResult<u64> {
    if reg > 17 {
        return Err(SdeiError::InvalidParameters);
    }
    smc::sdei_event_context(reg)
}

/// Get the interrupted PSTATE from event context.
#[inline]
pub fn get_interrupted_pstate() -> SdeiResult<u64> {
    smc::sdei_event_context(smc::context_param::PSTATE)
}

// =============================================================================
// Global SDEI Instance
// =============================================================================

/// Global SDEI instance.
///
/// Use this for convenience instead of creating your own Sdei instance.
pub static SDEI: Sdei = Sdei::new();
