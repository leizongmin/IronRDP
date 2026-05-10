//! RDP-UDP2 packet header (MS-RDPEUDP2 section 2.2.1.1).
//!
//! Header layout (2 bytes, big-endian):
//! ```text
//! |0           11|12          15|
//! |  Flags (12b) |LogWinSz(4b) |
//! ```

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct HeaderFlags: u16 {
        const ACK          = 0x001;
        const DATA         = 0x004;
        const ACKVEC       = 0x008;
        const AOA          = 0x010;
        const OVERHEADSIZE = 0x040;
        const DELAYACKINFO = 0x100;
    }
}

impl HeaderFlags {
    pub fn from_be(raw: u16) -> Self {
        Self::from_bits_truncate(raw >> 4)
    }

    pub fn to_be(self) -> u16 {
        self.bits() << 4
    }
}

/// 2-byte RDP-UDP2 packet header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Udp2Header {
    pub flags: HeaderFlags,
    /// Log2 of max buffer size in MTU multiples.
    pub log_window_size: u8,
}

impl Udp2Header {
    pub const SIZE: usize = 2;

    pub fn new(flags: HeaderFlags, log_window_size: u8) -> Self {
        Self { flags, log_window_size }
    }

    pub fn encode(&self, buf: &mut [u8; Self::SIZE]) {
        let raw = self.flags.to_be() | ((self.log_window_size as u16) & 0x0F);
        buf[0] = (raw >> 8) as u8;
        buf[1] = raw as u8;
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Udp2DecodeError> {
        if buf.len() < Self::SIZE {
            return Err(Udp2DecodeError::TruncatedHeader);
        }
        let raw = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = HeaderFlags::from_be(raw);
        let log_window_size = (raw & 0x0F) as u8;
        Ok(Self { flags, log_window_size })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Udp2DecodeError {
    TruncatedHeader,
    InvalidFlags,
    TruncatedPayload { expected: usize, actual: usize },
}
