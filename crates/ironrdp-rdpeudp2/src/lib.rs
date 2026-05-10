//! RDPEUDP2 (reliable UDP transport) PDU encode/decode.
//!
//! Implements the MS-RDPEUDP2 packet format for RDP UDP transport.
//! The protocol provides reliable, ordered delivery over UDP with
//! acknowledgment and retransmission.

#![cfg_attr(not(feature = "std"), no_std)]

mod header;
mod ack;
mod data;

pub use header::*;
pub use ack::*;
pub use data::*;
