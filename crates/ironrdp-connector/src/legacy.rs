use std::borrow::Cow;
use std::cell::RefCell;

use ironrdp_core::{Decode, Encode, WriteBuf, decode, encode_vec};
use ironrdp_pdu::crypto::rc4::Rc4;
use ironrdp_pdu::rdp;
use ironrdp_pdu::rdp::headers::{BASIC_SECURITY_HEADER_SIZE, BasicSecurityHeaderFlags, ServerDeactivateAll};
use ironrdp_pdu::rdp::multitransport::MultitransportRequestPdu;
use ironrdp_pdu::x224::X224;

use crate::{ConnectorError, ConnectorErrorExt as _, ConnectorResult, reason_err};

// OmniTerm: thread-local RC4 for standard RDP security
thread_local! {
    static RC4_DECRYPTOR: RefCell<Option<Rc4>> = const { RefCell::new(None) };
    static RC4_ENCRYPTOR: RefCell<Option<Rc4>> = const { RefCell::new(None) };
    static MAC_KEY: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// Set the RC4 decryptor (server → client) for standard RDP security.
pub fn set_rc4_decryptor(rc4: Rc4) {
    RC4_DECRYPTOR.with(|cell| {
        *cell.borrow_mut() = Some(rc4);
    });
}

/// Set the RC4 encryptor (client → server) for standard RDP security.
pub fn set_rc4_encryptor(rc4: Rc4) {
    RC4_ENCRYPTOR.with(|cell| {
        *cell.borrow_mut() = Some(rc4);
    });
}

/// Set the MAC key for standard RDP security data signatures.
pub fn set_mac_key(key: Vec<u8>) {
    MAC_KEY.with(|cell| {
        *cell.borrow_mut() = Some(key);
    });
}

/// Clear both RC4 instances and MAC key.
pub fn clear_rc4() {
    RC4_DECRYPTOR.with(|cell| { *cell.borrow_mut() = None; });
    RC4_ENCRYPTOR.with(|cell| { *cell.borrow_mut() = None; });
    MAC_KEY.with(|cell| { *cell.borrow_mut() = None; });
}

/// Decrypt data using the thread-local RC4 decryptor.
/// Returns None if no decryptor is set.
pub fn decrypt_with_rc4(data: &[u8]) -> Option<Vec<u8>> {
    RC4_DECRYPTOR.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if let Some(ref mut rc4) = *borrow {
            Some(rc4.process(data))
        } else {
            None
        }
    })
}

/// Public wrapper for outgoing encryption (used by connection.rs).
pub fn encrypt_outgoing_user_data_pub(data: &[u8]) -> Vec<u8> {
    encrypt_outgoing_user_data(data)
}

/// Check if the RC4 encryptor is set.
pub fn has_rc4_encryptor() -> bool {
    RC4_ENCRYPTOR.with(|cell| cell.borrow().is_some())
}

/// Compute MAC using the thread-local MAC key.
pub fn compute_mac_thread_local(data: &[u8]) -> [u8; 8] {
    MAC_KEY.with(|cell| {
        let borrow = cell.borrow();
        if let Some(ref mac_key) = *borrow {
            crate::standard_security::compute_mac(mac_key, data, 0)
        } else {
            [0u8; 8]
        }
    })
}

/// RC4 encrypt data using the thread-local encryptor.
pub fn rc4_encrypt_thread_local(data: &[u8]) -> Vec<u8> {
    RC4_ENCRYPTOR.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if let Some(ref mut rc4) = *borrow {
            rc4.process(data)
        } else {
            data.to_vec()
        }
    })
}

/// Encrypt outgoing user_data for standard RDP security.
///
/// Strips any inner security header (e.g. SEC_INFO_PKT) from the data,
/// computes MAC over the inner PDU payload, RC4-encrypts just the payload,
/// and sends MAC in clear between security header and encrypted data.
///
/// Format: [security_header(4, inner_flags|SEC_ENCRYPT)] + [MAC(8, clear)] + [RC4-encrypted(inner_data)]
fn encrypt_outgoing_user_data(data: &[u8]) -> Vec<u8> {
    let has_encryptor = RC4_ENCRYPTOR.with(|cell| cell.borrow().is_some());
    if !has_encryptor {
        return data.to_vec();
    }

    // Parse inner security header to extract PDU type flags (SEC_INFO_PKT, SEC_LICENSE_PKT, etc.)
    // and strip it — the outer header will carry both the PDU type flag and SEC_ENCRYPT.
    let (pdu_flags, inner_data) = if data.len() >= BASIC_SECURITY_HEADER_SIZE {
        let flags_raw = u16::from_le_bytes([data[0], data[1]]);
        let flags_hi = u16::from_le_bytes([data[2], data[3]]);
        if flags_hi == 0 && BasicSecurityHeaderFlags::from_bits(flags_raw).is_some() {
            let flags = BasicSecurityHeaderFlags::from_bits_retain(flags_raw);
            // Keep only PDU type flags, remove SEC_ENCRYPT if present
            let pdu_flags = flags & !BasicSecurityHeaderFlags::ENCRYPT;
            eprintln!("[encrypt_outgoing] stripping inner header: flags={:04x} -> pdu_flags={:04x}, inner_data_len={}", flags_raw, pdu_flags.bits(), data.len() - BASIC_SECURITY_HEADER_SIZE);
            (pdu_flags, &data[BASIC_SECURITY_HEADER_SIZE..])
        } else {
            eprintln!("[encrypt_outgoing] no valid inner header: flags_raw={:04x} flags_hi={:04x}", flags_raw, flags_hi);
            (BasicSecurityHeaderFlags::empty(), data)
        }
    } else {
        eprintln!("[encrypt_outgoing] data too short for header: len={}", data.len());
        (BasicSecurityHeaderFlags::empty(), data)
    };

    // Compute MAC over the inner PDU data (without security header)
    let mac_bytes = MAC_KEY.with(|cell| {
        let borrow = cell.borrow();
        if let Some(ref mac_key) = *borrow {
            Some(crate::standard_security::compute_mac(mac_key, inner_data, 0))
        } else {
            None
        }
    });
    let mac_bytes = mac_bytes.unwrap_or([0u8; 8]);

    // RC4-encrypt ONLY the inner data (MAC is sent in clear)
    let encrypted = RC4_ENCRYPTOR.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if let Some(ref mut rc4) = *borrow {
            Some(rc4.process(inner_data))
        } else {
            None
        }
    });

    match encrypted {
        Some(ciphertext) => {
            let combined_flags = pdu_flags | BasicSecurityHeaderFlags::ENCRYPT | BasicSecurityHeaderFlags::SECURE_CHECKSUM;
            // Format: [Security Header (4)] [MAC (8, clear)] [Encrypted Data]
            let mut result = Vec::with_capacity(BASIC_SECURITY_HEADER_SIZE + 8 + ciphertext.len());
            result.extend_from_slice(&combined_flags.bits().to_le_bytes());
            result.extend_from_slice(&0u16.to_le_bytes());
            result.extend_from_slice(&mac_bytes);
            result.extend_from_slice(&ciphertext);
            result
        }
        None => data.to_vec(),
    }
}

pub fn encode_send_data_request<T>(
    initiator_id: u16,
    channel_id: u16,
    user_msg: &T,
    buf: &mut WriteBuf,
) -> ConnectorResult<usize>
where
    T: Encode,
{
    let raw_data = encode_vec(user_msg).map_err(ConnectorError::encode)?;

    // OmniTerm: encrypt outgoing user_data if RC4 encryptor is set
    eprintln!("[legacy] encode_send_data_request: raw_data_len={} first4={:02x?}", raw_data.len(), &raw_data[..4.min(raw_data.len())]);
    let user_data = encrypt_outgoing_user_data(&raw_data);

    let pdu = ironrdp_pdu::mcs::SendDataRequest {
        initiator_id,
        channel_id,
        user_data: Cow::Owned(user_data),
    };

    let written = ironrdp_core::encode_buf(&X224(pdu), buf).map_err(ConnectorError::encode)?;

    Ok(written)
}

#[derive(Debug, Clone, Copy)]
pub struct SendDataIndicationCtx<'a> {
    pub initiator_id: u16,
    pub channel_id: u16,
    pub user_data: &'a [u8],
}

impl<'a> SendDataIndicationCtx<'a> {
    pub fn decode_user_data<'de, T>(&self) -> ConnectorResult<T>
    where
        T: Decode<'de>,
        'a: 'de,
    {
        let msg = decode::<T>(self.user_data).map_err(ConnectorError::decode)?;
        Ok(msg)
    }
}

pub fn decode_send_data_indication(src: &[u8]) -> ConnectorResult<SendDataIndicationCtx<'_>> {
    use ironrdp_pdu::mcs::McsMessage;

    let mcs_msg = decode::<X224<McsMessage<'_>>>(src).map_err(ConnectorError::decode)?;

    match mcs_msg.0 {
        McsMessage::SendDataIndication(msg) => {
            let Cow::Borrowed(user_data) = msg.user_data else {
                unreachable!()
            };

            Ok(SendDataIndicationCtx {
                initiator_id: msg.initiator_id,
                channel_id: msg.channel_id,
                user_data,
            })
        }
        McsMessage::DisconnectProviderUltimatum(msg) => Err(reason_err!(
            "decode_send_data_indication",
            "received disconnect provider ultimatum: {:?}",
            msg.reason
        )),
        _ => Err(reason_err!(
            "decode_send_data_indication",
            "unexpected MCS message: {}",
            ironrdp_core::name(&mcs_msg)
        )),
    }
}

pub fn encode_share_control(
    initiator_id: u16,
    channel_id: u16,
    share_id: u32,
    pdu: rdp::headers::ShareControlPdu,
    buf: &mut WriteBuf,
) -> ConnectorResult<usize> {
    let pdu_source = initiator_id;

    let share_control_header = rdp::headers::ShareControlHeader {
        share_control_pdu: pdu,
        pdu_source,
        share_id,
    };

    encode_send_data_request(initiator_id, channel_id, &share_control_header, buf)
}

#[derive(Debug, Clone)]
pub struct ShareControlCtx {
    pub initiator_id: u16,
    pub channel_id: u16,
    pub share_id: u32,
    pub pdu_source: u16,
    pub pdu: rdp::headers::ShareControlPdu,
}

pub fn decode_share_control(ctx: SendDataIndicationCtx<'_>) -> ConnectorResult<ShareControlCtx> {
    // OmniTerm: handle standard RDP security (RC4 encryption).
    let decrypted;
    let user_data = if ctx.user_data.len() >= BASIC_SECURITY_HEADER_SIZE {
        let flags_raw = u16::from_le_bytes([ctx.user_data[0], ctx.user_data[1]]);
        let flags_hi = u16::from_le_bytes([ctx.user_data[2], ctx.user_data[3]]);
        let flags = BasicSecurityHeaderFlags::from_bits_retain(flags_raw);

        if flags_hi == 0 && BasicSecurityHeaderFlags::from_bits(flags_raw).is_some() {
            let encrypted = flags.contains(BasicSecurityHeaderFlags::ENCRYPT);
            if encrypted {
                const MAC_SIZE: usize = 8;
                if ctx.user_data.len() < BASIC_SECURITY_HEADER_SIZE + MAC_SIZE {
                    return Err(reason_err!(
                        "decode_share_control",
                        "encrypted security header is shorter than MAC trailer"
                    ));
                }
                let ciphertext = &ctx.user_data[BASIC_SECURITY_HEADER_SIZE + MAC_SIZE..];

                // Use thread-local RC4 decryptor
                decrypted = RC4_DECRYPTOR.with(|cell| {
                    let mut borrow = cell.borrow_mut();
                    if let Some(ref mut rc4) = *borrow {
                        Some(rc4.process(ciphertext))
                    } else {
                        None
                    }
                });

                match decrypted {
                    Some(ref plain) => plain.as_slice(),
                    None => {
                        tracing::warn!("SEC_ENCRYPT set but no RC4 decryptor available");
                        &ctx.user_data[BASIC_SECURITY_HEADER_SIZE + MAC_SIZE..]
                    }
                }
            } else {
                // Not encrypted, just strip the 4-byte security header
                &ctx.user_data[BASIC_SECURITY_HEADER_SIZE..]
            }
        } else {
            // No security header — standard enhanced security path
            ctx.user_data
        }
    } else {
        ctx.user_data
    };

    let user_msg = decode::<rdp::headers::ShareControlHeader>(user_data).map_err(ConnectorError::decode)?;

    Ok(ShareControlCtx {
        initiator_id: ctx.initiator_id,
        channel_id: ctx.channel_id,
        share_id: user_msg.share_id,
        pdu_source: user_msg.pdu_source,
        pdu: user_msg.share_control_pdu,
    })
}

pub fn encode_share_data(
    initiator_id: u16,
    channel_id: u16,
    share_id: u32,
    pdu: rdp::headers::ShareDataPdu,
    buf: &mut WriteBuf,
) -> ConnectorResult<usize> {
    let share_data_header = rdp::headers::ShareDataHeader {
        share_data_pdu: pdu,
        stream_priority: rdp::headers::StreamPriority::Medium,
        compression_flags: rdp::headers::CompressionFlags::empty(),
        compression_type: rdp::client_info::CompressionType::K8, // ignored if CompressionFlags::empty()
    };

    let share_control_pdu = rdp::headers::ShareControlPdu::Data(share_data_header);

    encode_share_control(initiator_id, channel_id, share_id, share_control_pdu, buf)
}

#[derive(Debug, Clone)]
pub struct ShareDataCtx {
    pub initiator_id: u16,
    pub channel_id: u16,
    pub share_id: u32,
    pub pdu_source: u16,
    pub pdu: rdp::headers::ShareDataPdu,
}

pub fn decode_share_data(ctx: SendDataIndicationCtx<'_>) -> ConnectorResult<ShareDataCtx> {
    let ctx = decode_share_control(ctx)?;

    let rdp::headers::ShareControlPdu::Data(share_data_header) = ctx.pdu else {
        return Err(reason_err!(
            "decode_share_data",
            "received unexpected Share Control PDU: got {} (expected Data PDU)",
            ctx.pdu.as_short_name(),
        ));
    };

    Ok(ShareDataCtx {
        initiator_id: ctx.initiator_id,
        channel_id: ctx.channel_id,
        share_id: ctx.share_id,
        pdu_source: ctx.pdu_source,
        pdu: share_data_header.share_data_pdu,
    })
}

pub enum IoChannelPdu {
    Data(ShareDataCtx),
    DeactivateAll(ServerDeactivateAll),
    /// Server Initiate Multitransport Request PDU.
    ///
    /// Received when the server wants the client to establish a sideband UDP transport.
    MultitransportRequest(MultitransportRequestPdu),
}

pub fn decode_io_channel(ctx: SendDataIndicationCtx<'_>) -> ConnectorResult<IoChannelPdu> {
    // Multitransport PDUs use BasicSecurityHeader (flags:u16, flagsHi:u16) instead
    // of the ShareControlHeader (totalLength:u16, pduType:u16, ...) used by all
    // other IO channel PDUs. We discriminate by checking flagsHi == 0 (ShareControl
    // has pduType there, which is always non-zero) and requiring flags to be a valid
    // BasicSecurityHeaderFlags combination.
    if ctx.user_data.len() >= BASIC_SECURITY_HEADER_SIZE {
        let flags_raw = u16::from_le_bytes([ctx.user_data[0], ctx.user_data[1]]);
        let flags_hi = u16::from_le_bytes([ctx.user_data[2], ctx.user_data[3]]);

        if flags_hi == 0 {
            if let Some(flags) = BasicSecurityHeaderFlags::from_bits(flags_raw) {
                if flags.contains(BasicSecurityHeaderFlags::TRANSPORT_REQ) {
                    if let Ok(pdu) = decode::<MultitransportRequestPdu>(ctx.user_data) {
                        return Ok(IoChannelPdu::MultitransportRequest(pdu));
                    }
                }
            }
        }
    }

    let ctx = decode_share_control(ctx)?;

    match ctx.pdu {
        rdp::headers::ShareControlPdu::ServerDeactivateAll(deactivate_all) => {
            Ok(IoChannelPdu::DeactivateAll(deactivate_all))
        }
        rdp::headers::ShareControlPdu::Data(share_data_header) => {
            let share_data_ctx = ShareDataCtx {
                initiator_id: ctx.initiator_id,
                channel_id: ctx.channel_id,
                share_id: ctx.share_id,
                pdu_source: ctx.pdu_source,
                pdu: share_data_header.share_data_pdu,
            };

            Ok(IoChannelPdu::Data(share_data_ctx))
        }
        other => Err(reason_err!(
            "decode_io_channel",
            "received unexpected Share Control PDU: got {} (expected Data PDU or Server Deactivate All PDU)",
            other.as_short_name(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use ironrdp_core::encode_vec;
    use ironrdp_pdu::crypto::rc4::Rc4;
    use ironrdp_pdu::rdp;
    use ironrdp_pdu::rdp::headers::{BasicSecurityHeaderFlags, ShareControlHeader, ShareControlPdu, ServerDeactivateAll};

    use super::{SendDataIndicationCtx, decode_share_control, set_rc4_decryptor};

    #[test]
    fn decode_share_control_skips_cleartext_mac_for_standard_security() {
        let share_control = ShareControlHeader {
            share_control_pdu: ShareControlPdu::ServerDeactivateAll(ServerDeactivateAll),
            pdu_source: 1001,
            share_id: 0x1122_3344,
        };
        let plaintext = encode_vec(&share_control).expect("share control should encode");
        let key = [0x42u8; 16];
        let ciphertext = Rc4::new(&key).process(&plaintext);

        set_rc4_decryptor(Rc4::new(&key));

        let mut user_data = Vec::with_capacity(4 + 8 + ciphertext.len());
        user_data.extend_from_slice(&BasicSecurityHeaderFlags::ENCRYPT.bits().to_le_bytes());
        user_data.extend_from_slice(&0u16.to_le_bytes());
        user_data.extend_from_slice(&[0xAA; 8]);
        user_data.extend_from_slice(&ciphertext);

        let decoded = decode_share_control(SendDataIndicationCtx {
            initiator_id: 1001,
            channel_id: 1003,
            user_data: &user_data,
        })
        .expect("share control should decode");

        assert_eq!(decoded.share_id, 0x1122_3344);
        assert_eq!(decoded.pdu_source, 1001);
        assert!(matches!(
            decoded.pdu,
            rdp::headers::ShareControlPdu::ServerDeactivateAll(_)
        ));
    }
}
