//! Shared Reticulum identity beacon (same wire format for ESP-NOW and HaLow UART).

use ed25519_dalek::Signature;
use reticulum::hash::AddressHash;
use reticulum::identity::{Identity, PrivateIdentity};

pub const BEACON_MAGIC: &[u8] = b"RNS0";
pub const BEACON_LEN: usize = 132;
pub const BEACON_HEX_LEN: usize = BEACON_LEN * 2;

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for b in data {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

pub fn beacon_checksums(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < BEACON_LEN {
        return None;
    }
    Some((fnv1a32(&data[..68]), fnv1a32(&data[68..BEACON_LEN])))
}

#[derive(Copy, Clone, Debug)]
pub enum BeaconDecodeError {
    TooShort,
    BadMagic,
    BadVerifyingKey,
    BadSignature,
}

pub fn encode_beacon(id: &PrivateIdentity, out: &mut [u8]) -> Option<usize> {
    if out.len() < BEACON_LEN {
        return None;
    }
    let id_pub = id.as_identity();
    out[0..4].copy_from_slice(BEACON_MAGIC);
    out[4..36].copy_from_slice(id_pub.public_key.as_bytes());
    out[36..68].copy_from_slice(id_pub.verifying_key_bytes());
    let sig = id.sign(&out[0..68]);
    out[68..BEACON_LEN].copy_from_slice(&sig.to_bytes());
    Some(BEACON_LEN)
}

fn hex_encode(src: &[u8], out: &mut [u8]) -> Option<usize> {
    if out.len() < src.len() * 2 {
        return None;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in src.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    Some(src.len() * 2)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(src: &[u8], out: &mut [u8]) -> Option<usize> {
    if src.len() % 2 != 0 || out.len() < src.len() / 2 {
        return None;
    }
    for i in 0..(src.len() / 2) {
        let hi = hex_nibble(src[i * 2])?;
        let lo = hex_nibble(src[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(src.len() / 2)
}

fn extract_beacon_raw_from_mixed_hex(data: &[u8]) -> Option<[u8; BEACON_LEN]> {
    // Decode as many hex digits as possible, then find raw magic in decoded bytes.
    let mut hex_buf = [0u8; 2048];
    let mut hex_len = 0usize;
    for b in data {
        if b.is_ascii_hexdigit() {
            if hex_len < hex_buf.len() {
                hex_buf[hex_len] = *b;
                hex_len += 1;
            } else {
                break;
            }
        }
    }
    if hex_len < BEACON_HEX_LEN {
        return None;
    }
    if hex_len % 2 != 0 {
        hex_len -= 1;
    }

    let mut decoded = [0u8; 1024];
    let dec_len = hex_decode(&hex_buf[..hex_len], &mut decoded)?;
    if dec_len < BEACON_LEN {
        return None;
    }

    for i in 0..=dec_len - BEACON_LEN {
        if decoded[i..i + BEACON_MAGIC.len()] == *BEACON_MAGIC {
            let mut raw = [0u8; BEACON_LEN];
            raw.copy_from_slice(&decoded[i..i + BEACON_LEN]);
            return Some(raw);
        }
    }
    None
}

pub fn encode_beacon_hex(id: &PrivateIdentity, out: &mut [u8]) -> Option<usize> {
    let mut raw = [0u8; BEACON_LEN];
    let n = encode_beacon(id, &mut raw)?;
    hex_encode(&raw[..n], out)
}

pub fn decode_beacon(data: &[u8]) -> Option<Identity> {
    decode_beacon_verbose(data).ok()
}

pub fn decode_beacon_unverified(data: &[u8]) -> Option<Identity> {
    if data.len() < BEACON_LEN {
        return None;
    }
    if &data[0..4] != BEACON_MAGIC {
        return None;
    }
    Some(Identity::new_from_slices(&data[4..36], &data[36..68]))
}

pub fn decode_beacon_hex(data: &[u8]) -> Option<Identity> {
    let raw = extract_beacon_raw_from_mixed_hex(data)?;
    decode_beacon(&raw)
}

pub fn decode_beacon_hex_unverified(data: &[u8]) -> Option<Identity> {
    let raw = extract_beacon_raw_from_mixed_hex(data)?;
    decode_beacon_unverified(&raw)
}

pub fn decode_beacon_hex_verbose(data: &[u8]) -> Result<Identity, BeaconDecodeError> {
    let raw = extract_beacon_raw_from_mixed_hex(data).ok_or(BeaconDecodeError::TooShort)?;
    decode_beacon_verbose(&raw)
}

pub fn beacon_hex_checksums(data: &[u8]) -> Option<(u32, u32)> {
    let raw = extract_beacon_raw_from_mixed_hex(data)?;
    beacon_checksums(&raw)
}

pub fn decode_beacon_verbose(data: &[u8]) -> Result<Identity, BeaconDecodeError> {
    if data.len() < BEACON_LEN {
        return Err(BeaconDecodeError::TooShort);
    }
    if &data[0..4] != BEACON_MAGIC {
        return Err(BeaconDecodeError::BadMagic);
    }
    let mut verify_key = [0u8; 32];
    verify_key.copy_from_slice(&data[36..68]);
    if ed25519_dalek::VerifyingKey::from_bytes(&verify_key).is_err() {
        return Err(BeaconDecodeError::BadVerifyingKey);
    }
    let peer = Identity::new_from_slices(&data[4..36], &data[36..68]);
    let sig_bytes: [u8; 64] = data[68..BEACON_LEN]
        .try_into()
        .map_err(|_| BeaconDecodeError::TooShort)?;
    let sig = Signature::from_bytes(&sig_bytes);
    peer.verify(&data[0..68], &sig)
        .map_err(|_| BeaconDecodeError::BadSignature)?;
    Ok(peer)
}

pub fn print_local_addr(id: &PrivateIdentity) {
    use esp_println::println;
    let my_addr: AddressHash = id.as_identity().address_hash;
    println!("Local Reticulum address hash: {}", my_addr.to_hex_string());
}
