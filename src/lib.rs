//! SUA (SCCP User Adaptation Layer) codec per [RFC 3868].
//!
//! SUA carries the **SCCP user** (TCAP, and above it MAP / CAP / INAP) over an
//! IP network using SCTP as the transport. It is the SIGTRAN sibling of M3UA:
//! both use the same 8-byte common header and TLV parameter framing, but where
//! M3UA transports the MTP3 user on a point-code routing label, SUA transports
//! the SCCP user with **Global Title / SSN / Point Code** addressing, exactly as
//! SCCP does. In a Signalling Gateway, a SUA CLDT interworks one-for-one with an
//! SCCP UDT.
//!
//! This crate is the **wire format** only, the common header, the TLV
//! parameters, the GT/SSN/PC addresses and the whole-message encode/decode. It
//! does no I/O: the SCTP association belongs to the composing runtime, so the
//! codec stays portable and every consumer can unit-test against it.
//!
//! [RFC 3868]: https://www.rfc-editor.org/rfc/rfc3868.html
//!
//! # Example
//!
//! ```
//! use sua::{GlobalTitle, SuaAddress, SuaMessage, MessageType};
//!
//! // A CLDT carrying an SCCP-user (TCAP) payload between two GT+SSN addresses.
//! // Digits are synthetic (fictional +1-555 range), decimal point codes.
//! let source = SuaAddress::with_gt(GlobalTitle::e164("15550100"), Some(8));
//! let dest = SuaAddress::with_gt(GlobalTitle::e164("15550142"), Some(6));
//! let cldt = SuaMessage::cldt(42, 0, &source, &dest, 0, Some(15), vec![0x62, 0x40]).unwrap();
//!
//! let bytes = cldt.encode();
//! let decoded = SuaMessage::decode(&bytes).unwrap();
//! assert_eq!(decoded.message_type, MessageType::Cldt);
//! assert_eq!(decoded.destination_address().unwrap().gt_digits(), Some("15550142"));
//! ```
#![warn(missing_docs)]

/// Source / Destination addresses ([`SuaAddress`]), the [`GlobalTitle`] sub-
/// parameter, and the [`RoutingIndicator`].
pub mod address;
/// BCD packing for Global Title digits.
pub mod bcd;
/// The typed error returned by decode and validation ([`SuaError`]).
pub mod error;
/// The 8-byte common header, message classes, and message types.
pub mod header;
/// Whole SUA messages ([`SuaMessage`]) with typed builders and accessors.
pub mod message;
/// TLV parameters ([`Parameter`]) and the well-known parameter [`tags`].
pub mod parameter;

/// PyO3 bindings for the Python wheel (`--features python`).
#[cfg(feature = "python")]
pub mod python;

pub use address::{GlobalTitle, RoutingIndicator, SuaAddress};
pub use error::SuaError;
pub use header::{CommonHeader, MessageClass, MessageType, SCTP_PPID, VERSION};
pub use message::{
    pack_affected_point_codes, unpack_affected_point_codes, SuaMessage, DEFAULT_HOP_COUNTER,
};
pub use parameter::{tags, Parameter};
