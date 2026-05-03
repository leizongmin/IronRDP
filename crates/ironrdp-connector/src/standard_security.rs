//! Standard RDP Security helpers (Security Exchange, RC4 key derivation).
//!
//! Key derivation follows MS-RDPBCGR 5.3.5.1 (Non-FIPS), verified against FreeRDP.

use ironrdp_pdu::crypto::rc4::Rc4;
use ironrdp_pdu::gcc::EncryptionMethod;

/// Parse the server_cert from MCS Connect Response (proprietary RDP cert format).
/// Returns (modulus_bytes_LE, exponent).
pub fn parse_server_cert(server_cert: &[u8]) -> Result<(Vec<u8>, u32), &'static str> {
    if server_cert.len() < 16 {
        return Err("server_cert too short");
    }

    let blob_len = u16::from_le_bytes([server_cert[14], server_cert[15]]) as usize;
    if server_cert.len() < 16 + blob_len {
        return Err("server_cert too short for public key blob");
    }

    let blob = &server_cert[16..16 + blob_len];
    if blob.len() < 20 {
        return Err("RSA blob too short");
    }

    let magic = &blob[0..4];
    if magic != b"RSA1" {
        return Err("expected RSA1 magic");
    }

    let keylen = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    let pub_exp = u32::from_le_bytes([blob[16], blob[17], blob[18], blob[19]]);

    let modulus_len = keylen - 8;
    if blob.len() < 20 + modulus_len {
        return Err("RSA blob too short for modulus");
    }

    Ok((blob[20..20 + modulus_len].to_vec(), pub_exp))
}

/// Encrypt client_random with server's RSA public key (raw RSA, no padding).
/// The full 32-byte client random is encrypted.
pub fn encrypt_client_random(
    client_random: &[u8],
    modulus: &[u8],
    exponent: u32,
) -> Result<Vec<u8>, &'static str> {
    use num_bigint::BigUint;

    let n = BigUint::from_bytes_le(modulus);
    let e = BigUint::from(exponent);
    let m = BigUint::from_bytes_le(client_random);

    if m >= n {
        return Err("client random too large for modulus");
    }

    let c = m.modpow(&e, &n);
    let mut result = c.to_bytes_le();
    // Pad to modulus length
    if result.len() < modulus.len() {
        result.resize(modulus.len(), 0);
    }
    Ok(result)
}

/// Encrypt the password for standard RDP security using the server's RSA public key.
/// Per MS-RDPBCGR 5.3.6.1:
/// 1. Convert password to UTF-16LE (Unicode) with null terminator
/// 2. Pad with zeros to modulus length
/// 3. Reverse byte order
/// 4. Raw RSA encrypt with server's public key
pub fn encrypt_password(
    password: &str,
    modulus: &[u8],
    exponent: u32,
) -> Result<Vec<u8>, &'static str> {
    use num_bigint::BigUint;

    // 1. UTF-16LE with null terminator
    let mut bytes: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    bytes.extend_from_slice(&[0u8, 0u8]); // null terminator

    // 2. Pad to modulus length with zeros
    bytes.resize(modulus.len(), 0);

    // 3. Reverse byte order
    bytes.reverse();

    // 4. Raw RSA encrypt
    let n = BigUint::from_bytes_le(modulus);
    let e = BigUint::from(exponent);

    if BigUint::from_bytes_le(&bytes) >= n {
        return Err("encrypted password too large for modulus");
    }

    let c = BigUint::from_bytes_le(&bytes).modpow(&e, &n);
    let mut result = c.to_bytes_le();
    if result.len() < modulus.len() {
        result.resize(modulus.len(), 0);
    }
    Ok(result)
}

/// Build the Security Exchange PDU (MCS SendDataRequest wrapping security header + encrypted random).
pub fn build_security_exchange_pdu(
    encrypted_client_random: &[u8],
    user_channel_id: u16,
    io_channel_id: u16,
) -> Vec<u8> {
    use ironrdp_pdu::rdp::headers::BasicSecurityHeaderFlags;
    use ironrdp_pdu::x224::X224;
    use std::borrow::Cow;

    let mut body = Vec::new();
    body.extend_from_slice(&(BasicSecurityHeaderFlags::EXCHANGE_PKT | BasicSecurityHeaderFlags::LICENSE_ENCRYPT_SC).bits().to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // flags_hi
    // Per MS-RDPBCGR 2.2.1.10.1: length field = encrypted random length + 8 (padding)
    let length_field = (encrypted_client_random.len() as u32) + 8;
    body.extend_from_slice(&length_field.to_le_bytes());
    body.extend_from_slice(encrypted_client_random);
    body.extend_from_slice(&[0u8; 8]); // 8 bytes of zero padding (FreeRDP compatible)

    let pdu = ironrdp_pdu::mcs::SendDataRequest {
        initiator_id: user_channel_id,
        channel_id: io_channel_id,
        user_data: Cow::Owned(body),
    };

    ironrdp_core::encode_vec(&X224(pdu)).expect("encode security exchange PDU")
}

/// Derived keys for standard RDP security.
pub struct RdpSecurityKeys {
    pub mac_key: Vec<u8>,
    /// RC4 for client→server encryption
    pub encrypt_key: Rc4,
    /// RC4 for server→client decryption
    pub decrypt_key: Rc4,
}

/// Derive all three standard RDP security keys per MS-RDPBCGR 5.3.5.1.
pub fn derive_keys(
    server_random: &[u8],
    client_random: &[u8],
    encryption_method: EncryptionMethod,
) -> RdpSecurityKeys {
    // Step 1: PreMasterSecret = First192Bits(ClientRandom) + First192Bits(ServerRandom)
    let pre_master = [&client_random[..24], &server_random[..24]].concat();

    // Step 2: MasterSecret = SaltedHash(PreMasterSecret, 'A') + ... + SaltedHash(PreMasterSecret, 'CCC')
    let ms1 = salted_hash(&pre_master, b"A", client_random, server_random);
    let ms2 = salted_hash(&pre_master, b"BB", client_random, server_random);
    let ms3 = salted_hash(&pre_master, b"CCC", client_random, server_random);
    let master_secret = [&ms1[..], &ms2[..], &ms3[..]].concat();

    // Step 3: SessionKeyBlob = SaltedHash(MasterSecret, 'X') + ... + SaltedHash(MasterSecret, 'ZZZ')
    let sk1 = salted_hash(&master_secret, b"X", client_random, server_random);
    let sk2 = salted_hash(&master_secret, b"YY", client_random, server_random);
    let sk3 = salted_hash(&master_secret, b"ZZZ", client_random, server_random);
    let session_key_blob = [&sk1[..], &sk2[..], &sk3[..]].concat();

    // Step 4: MACKey = First128Bits(SessionKeyBlob)
    let mac_key = session_key_blob[..16].to_vec();

    // Step 5: Client encrypt/decrypt keys via FinalHash = MD5(K + ClientRandom + ServerRandom)
    // Client: encrypt_key = MD5(SessionKeyBlob[32..48] + ClientRandom + ServerRandom)
    // Client: decrypt_key = MD5(SessionKeyBlob[16..32] + ClientRandom + ServerRandom)
    let raw_encrypt = final_hash(&session_key_blob[32..48], client_random, server_random);
    let raw_decrypt = final_hash(&session_key_blob[16..32], client_random, server_random);

    let encrypt_rc4_key = apply_key_reduction(raw_encrypt, encryption_method);
    let decrypt_rc4_key = apply_key_reduction(raw_decrypt, encryption_method);

    eprintln!("[derive_keys] session_key_blob(first16)={:02x?}", &session_key_blob[..16]);
    eprintln!("[derive_keys] raw_encrypt_key={:02x?}", raw_encrypt);
    eprintln!("[derive_keys] raw_decrypt_key={:02x?}", raw_decrypt);
    eprintln!("[derive_keys] encrypt_rc4_key={:02x?}", encrypt_rc4_key);
    eprintln!("[derive_keys] decrypt_rc4_key={:02x?}", decrypt_rc4_key);

    RdpSecurityKeys {
        mac_key,
        encrypt_key: Rc4::new(&encrypt_rc4_key),
        decrypt_key: Rc4::new(&decrypt_rc4_key),
    }
}

/// Compute the MAC (data signature) for outgoing encrypted PDUs.
/// For 128-bit encryption (salted MAC):
///   MACSignature = First64Bits(MD5(MACKey + pad2 + SHA1(MACKey + pad1 + length_LE + data + encryptionCount_LE)))
pub fn compute_mac(mac_key: &[u8], data: &[u8], encryption_count: u32) -> [u8; 8] {
    let pad1 = [0x36u8; 40];
    let pad2 = [0x5Cu8; 48];

    // SHA1(MACKey + pad1 + length_LE + data + encryptionCount_LE)
    let len_le = (data.len() as u32).to_le_bytes();
    let count_le = encryption_count.to_le_bytes();
    let sha1_digest = sha1_of(&[mac_key, &pad1, &len_le[..], data, &count_le[..]]);

    // MD5(MACKey + pad2 + SHA1_digest)
    let md5_digest = md5_of(&[mac_key, &pad2, &sha1_digest[..]]);

    let mut result = [0u8; 8];
    result.copy_from_slice(&md5_digest[..8]);
    result
}

/// SaltedHash(S, I) = MD5(S + SHA1(I + S + ClientRandom + ServerRandom))
fn salted_hash(salt: &[u8], pad: &[u8], client_random: &[u8], server_random: &[u8]) -> [u8; 16] {
    let sha1 = sha1_of(&[pad, salt, client_random, server_random]);
    md5_of(&[salt, &sha1[..]])
}

/// FinalHash(K) = MD5(K + ClientRandom + ServerRandom)
fn final_hash(k: &[u8], client_random: &[u8], server_random: &[u8]) -> [u8; 16] {
    md5_of(&[k, client_random, server_random])
}

/// Apply key entropy reduction per MS-RDPBCGR 5.3.5.1 Table 1.
fn apply_key_reduction(mut key: [u8; 16], method: EncryptionMethod) -> Vec<u8> {
    let salt_40: [u8; 3] = [0xD1, 0x26, 0x9E];
    if method.contains(EncryptionMethod::BIT_128) {
        key.to_vec()
    } else if method.contains(EncryptionMethod::BIT_56) {
        key[0] = 0xD1;
        key[1] &= 0x3F;
        key[..8].to_vec()
    } else {
        key[..3].copy_from_slice(&salt_40);
        key[3] &= 0x03;
        key[..8].to_vec()
    }
}

fn md5_of(parts: &[&[u8]]) -> [u8; 16] {
    let mut ctx = md5::Context::new();
    for p in parts {
        ctx.consume(p);
    }
    ctx.compute().0
}

fn sha1_of(parts: &[&[u8]]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
