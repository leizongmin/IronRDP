//! ACK and ACKVEC payloads (MS-RDPEUDP2 sections 2.2.1.2.1, 2.2.1.2.4, 2.2.1.2.6).

use crate::header::Udp2DecodeError;

/// ACK payload — acknowledges received sequence numbers.
/// Layout: AckSequenceNumber (4 bytes, big-endian).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckPayload {
    pub ack_sequence: u32,
}

impl AckPayload {
    pub const SIZE: usize = 4;

    pub fn encode(&self, buf: &mut [u8; Self::SIZE]) {
        buf.copy_from_slice(&self.ack_sequence.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Udp2DecodeError> {
        if buf.len() < Self::SIZE {
            return Err(Udp2DecodeError::TruncatedPayload {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        Ok(Self {
            ack_sequence: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        })
    }
}

/// Ack-of-Acks (AOA) payload — acknowledges ACKs.
/// Layout: AckOfAcksSequenceNumber (4 bytes, big-endian).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckOfAcksPayload {
    pub ack_of_acks_sequence: u32,
}

impl AckOfAcksPayload {
    pub const SIZE: usize = 4;

    pub fn encode(&self, buf: &mut [u8; Self::SIZE]) {
        buf.copy_from_slice(&self.ack_of_acks_sequence.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Udp2DecodeError> {
        if buf.len() < Self::SIZE {
            return Err(Udp2DecodeError::TruncatedPayload {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        Ok(Self {
            ack_of_acks_sequence: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        })
    }
}

/// ACK Vector payload — bit vector of acknowledged sequence ranges.
/// Layout: AckVectorLength (2 bytes, BE) + AckVector (variable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckVecPayload {
    pub ack_vec: Vec<u8>,
}

impl AckVecPayload {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.ack_vec.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.ack_vec);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Udp2DecodeError> {
        if buf.len() < 2 {
            return Err(Udp2DecodeError::TruncatedPayload { expected: 2, actual: buf.len() });
        }
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if buf.len() < 2 + len {
            return Err(Udp2DecodeError::TruncatedPayload { expected: 2 + len, actual: buf.len() });
        }
        Ok(Self {
            ack_vec: buf[2..2 + len].to_vec(),
        })
    }
}
