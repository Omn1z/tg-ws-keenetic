//! Telegram obfuscated transport key derivation. Payloads are transformed in
//! place; the four stream states are all that a relay connection retains.

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io;

pub type AesCtr = ctr::Ctr128BE<Aes256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

impl Protocol {
    pub fn tag(self) -> [u8; 4] {
        match self {
            Self::Abridged => [0xef; 4],
            Self::Intermediate => [0xee; 4],
            Self::PaddedIntermediate => [0xdd; 4],
        }
    }
}

pub struct ClientHandshake {
    /// Preserve the sign (media) and the 10000 test-environment offset.
    pub dc_index: i16,
    pub protocol: Protocol,
    pub prekey_iv: [u8; 48],
}

fn secret_key(prekey: &[u8], secret: &[u8; 16]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(prekey);
    hash.update(secret);
    hash.finalize().into()
}

fn cipher(key: &[u8], iv: &[u8]) -> AesCtr {
    // Every caller supplies a fixed-size key/IV slice from a checked handshake.
    AesCtr::new(key.into(), iv.into())
}

pub fn parse_client_handshake(
    handshake: &[u8; 64],
    secret: &[u8; 16],
) -> io::Result<ClientHandshake> {
    let mut prekey_iv = [0; 48];
    prekey_iv.copy_from_slice(&handshake[8..56]);
    let key = secret_key(&prekey_iv[..32], secret);
    let mut plain = *handshake;
    cipher(&key, &prekey_iv[32..]).apply_keystream(&mut plain);
    let protocol = match &plain[56..60] {
        [0xef, 0xef, 0xef, 0xef] => Protocol::Abridged,
        [0xee, 0xee, 0xee, 0xee] => Protocol::Intermediate,
        [0xdd, 0xdd, 0xdd, 0xdd] => Protocol::PaddedIntermediate,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid MTProto secret or transport tag",
            ));
        }
    };
    Ok(ClientHandshake {
        dc_index: i16::from_le_bytes([plain[60], plain[61]]),
        protocol,
        prekey_iv,
    })
}

fn reserved(handshake: &[u8; 64]) -> bool {
    handshake[0] == 0xef
        || matches!(
            &handshake[..4],
            b"HEAD"
                | b"POST"
                | b"GET "
                | [0xee, 0xee, 0xee, 0xee]
                | [0xdd, 0xdd, 0xdd, 0xdd]
                | [0x16, 0x03, 0x01, 0x02]
        )
        || handshake[4..8] == [0; 4]
}

pub fn generate_relay_handshake(protocol: Protocol, dc_index: i16) -> [u8; 64] {
    let mut handshake = [0; 64];
    loop {
        OsRng.fill_bytes(&mut handshake);
        if !reserved(&handshake) {
            break;
        }
    }
    let mut plaintext = handshake;
    plaintext[56..60].copy_from_slice(&protocol.tag());
    plaintext[60..62].copy_from_slice(&dc_index.to_le_bytes());
    cipher(&handshake[8..40], &handshake[40..56]).apply_keystream(&mut plaintext);
    handshake[56..].copy_from_slice(&plaintext[56..]);
    handshake
}

pub struct CryptoContext {
    pub client_decrypt: AesCtr,
    pub client_encrypt: AesCtr,
    pub upstream_encrypt: AesCtr,
    pub upstream_decrypt: AesCtr,
}

pub fn build_context(
    client: &ClientHandshake,
    secret: &[u8; 16],
    relay_handshake: &[u8; 64],
) -> CryptoContext {
    let key = secret_key(&client.prekey_iv[..32], secret);
    let mut client_decrypt = cipher(&key, &client.prekey_iv[32..]);
    let mut reversed = client.prekey_iv;
    reversed.reverse();
    let key = secret_key(&reversed[..32], secret);
    let client_encrypt = cipher(&key, &reversed[32..]);
    client_decrypt.apply_keystream(&mut [0; 64]);

    let mut upstream_encrypt = cipher(&relay_handshake[8..40], &relay_handshake[40..56]);
    let mut reversed = [0; 48];
    reversed.copy_from_slice(&relay_handshake[8..56]);
    reversed.reverse();
    let upstream_decrypt = cipher(&reversed[..32], &reversed[32..]);
    upstream_encrypt.apply_keystream(&mut [0; 64]);

    CryptoContext {
        client_decrypt,
        client_encrypt,
        upstream_encrypt,
        upstream_decrypt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
    }

    fn client_init(secret: &[u8; 16], protocol: Protocol, dc: i16) -> [u8; 64] {
        let mut bytes = std::array::from_fn(|i| i as u8);
        let mut plain = bytes;
        plain[56..60].copy_from_slice(&protocol.tag());
        plain[60..62].copy_from_slice(&dc.to_le_bytes());
        cipher(&secret_key(&bytes[8..40], secret), &bytes[40..56]).apply_keystream(&mut plain);
        bytes[56..].copy_from_slice(&plain[56..]);
        bytes
    }

    #[test]
    fn nist_aes256_ctr_vector() {
        let key = decode::<32>("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv = decode::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let mut plain = decode::<64>("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        cipher(&key, &iv).apply_keystream(&mut plain);
        assert_eq!(plain, decode::<64>("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"));
    }

    #[test]
    fn handshake_authentication_preserves_media_and_test_dc() {
        let secret = *b"0123456789abcdef";
        for protocol in [
            Protocol::Abridged,
            Protocol::Intermediate,
            Protocol::PaddedIntermediate,
        ] {
            for dc in [1, -4, 203, 10001, -10003] {
                let wire = client_init(&secret, protocol, dc);
                let parsed = parse_client_handshake(&wire, &secret).unwrap();
                assert_eq!(parsed.dc_index, dc);
                assert_eq!(parsed.protocol, protocol);
                assert!(parse_client_handshake(&wire, b"fedcba9876543210").is_err());
            }
        }
    }

    #[test]
    fn relay_handshake_is_unreserved_and_has_signed_dc() {
        for protocol in [
            Protocol::Abridged,
            Protocol::Intermediate,
            Protocol::PaddedIntermediate,
        ] {
            for dc in [2, -4, 10002, -10003] {
                for _ in 0..32 {
                    let wire = generate_relay_handshake(protocol, dc);
                    assert!(!reserved(&wire));
                    let mut plain = wire;
                    cipher(&wire[8..40], &wire[40..56]).apply_keystream(&mut plain);
                    assert_eq!(plain[56..60], protocol.tag());
                    assert_eq!(i16::from_le_bytes([plain[60], plain[61]]), dc);
                }
            }
        }
    }

    /// Independent vectors generated by Flowseal v1.10.2's _build_crypto_ctx.
    /// Chunking crosses cipher blocks and verifies all four stream offsets.
    #[test]
    fn python_v1102_context_vectors() {
        let client = ClientHandshake {
            dc_index: 2,
            protocol: Protocol::Intermediate,
            prekey_iv: std::array::from_fn(|i| i as u8),
        };
        let relay = std::array::from_fn(|i| i as u8);
        let secret = decode::<16>("00112233445566778899aabbccddeeff");
        let context = build_context(&client, &secret, &relay);
        for (mut stream, expected) in [
            (context.client_decrypt, "d0a653a2fb91085271dd64ad23658e28273f8828e454dbe83c19aa596754c484f58101cd88c6d84575cfb4c9e2787831554213479764c20e9b08d4084ff32e062a0e62f82d4adc3fec268db8432723"),
            (context.client_encrypt, "3e8d10ed9442c3f6badfd3482eb47e422169d854a6540ef16e808eb17d349abd153e035b92e2983773f17308780297f18c0a10e23c21d04263bf81031566dac05d1e9b275ac8ba1fab8aea3fb4b0d1"),
            (context.upstream_encrypt, "33abc22c3df762492bbb9bb110acbd1bb3b4d7b9cce119e3348c0d001e5747f3a259f1a8afb4d78518a252da3bcd07a36b5a8e42a6bacd944c811c3c626bfffce0e7e2902be7f4829a1ee5aededd91"),
            (context.upstream_decrypt, "2e9fe074dbca01489cd33aef07287479c02fa5a9f026976ef45fecad041f6d4e456bffcc1c1eb632ae31c620025f76146313025bb8b8b46d6dcb9a77ba723ba0d16adace1aee7cb61f2afc088daa48"),
        ] {
            let mut payload: [u8; 79] = std::array::from_fn(|i| (i + 1) as u8);
            stream.apply_keystream(&mut payload[..7]);
            stream.apply_keystream(&mut payload[7..32]);
            stream.apply_keystream(&mut payload[32..]);
            assert_eq!(payload, decode::<79>(expected));
        }
    }
}
