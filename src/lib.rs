//! ARM Software Delegated Exception Interface (SDEI) driver.
//!
//! SDEI provides a mechanism for the OS to register handlers for system events
//! that can be delivered as Non-Maskable Interrupts (NMI). This is particularly
//! useful for implementing watchdog timers that need to execute even when
//! normal interrupts are disabled.
//!
//! # Architecture
//!
//! SDEI operates through SMC (Secure Monitor Call) interface to communicate
//! with the Secure Monitor running at EL3. The firmware (e.g., ARM Trusted
//! Firmware) implements the SDEI dispatcher.
//!
//! # Example
//!
//! ```no_run
//! use aarch64_sdei::{Sdei, SdeiEventFlags};
//!
//! // Initialize SDEI
//! let sdei = Sdei::new();
//! sdei.init().expect("SDEI init failed");
//!
//! // Register a private event handler
//! unsafe {
//!     sdei.event_register(
//!         0,  // Event number
//!         handler_entry as usize,
//!         0,  // Argument
//!         SdeiEventFlags::empty(),
//!         0,  // Affinity (ignored for private events)
//!     ).expect("Event register failed");
//! }
//!
//! sdei.event_enable(0).expect("Event enable failed");
//! ```

#![no_std]

pub mod event;
pub mod smc;

pub use event::{Sdei, SdeiEventFlags, SdeiEventInfo, SdeiEventType};
pub use smc::{SdeiError, SdeiResult, SdeiVersion};

/// SDEI event handler function signature.
///
/// # Arguments
/// * `event` - The event number that triggered
/// * `arg` - User-provided argument from registration
/// * `pc` - Program counter at the time of event
/// * `pstate` - Processor state at the time of event
///
/// # Safety
/// This handler runs in a special NMI-like context. It MUST NOT:
/// - Acquire any locks (spinlocks, mutexes, etc.)
/// - Allocate memory
/// - Call any functions that may block
///
/// It SHOULD only use:
/// - Atomic operations
/// - Per-CPU data structures
/// - Direct register/memory writes
pub type SdeiHandler = unsafe extern "C" fn(event: u32, arg: usize, pc: usize, pstate: usize);

/// Maximum number of events that can be registered.
pub const MAX_SDEI_EVENTS: usize = 32;

/// SDEI private event 0 - typically used for software-triggered NMI.
pub const SDEI_EVENT_SOFTWARE_NMI: u32 = 0;
