//! DATA payload — encapsulates user data in RDP-UDP2 packets
//! (MS-RDPEUDP2 sections 2.2.1.2.5, 2.2.1.2.7).

use crate::header::Udp2DecodeError;

/// DataHeader payload (MS-RDPEUDP2 section 2.2.1.2.5).
/// Layout: SequenceNumber (4 bytes, BE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataHeader {
    pub sequence_number: u32,
}

impl DataHeader {
    pub const SIZE: usize = 4;

    pub fn encode(&self, buf: &mut [u8; Self::SIZE]) {
        buf.copy_from_slice(&self.sequence_number.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Udp2DecodeError> {
        if buf.len() < Self::SIZE {
            return Err(Udp2DecodeError::TruncatedPayload {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        Ok(Self {
            sequence_number: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
        })
    }
}

/// Complete DATA payload: DataHeader + DataBody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataPayload {
    pub sequence_number: u32,
    pub body: Vec<u8>,
}

impl DataPayload {
    pub fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.body);
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Udp2DecodeError> {
        if buf.len() < 4 {
            return Err(Udp2DecodeError::TruncatedPayload { expected: 4, actual: buf.len() });
        }
        let seq = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok(Self {
            sequence_number: seq,
            body: buf[4..].to_vec(),
        })
    }
}
