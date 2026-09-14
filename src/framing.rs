//! Parse only MTProto length headers, allowing the bridge to stream a complete
//! WebSocket frame with constant memory even when a transport packet is large.

use crate::crypto::Protocol;
use std::io;

pub const MAX_PACKET_PAYLOAD: usize = 16 * 1024 * 1024;

pub fn header_len(first: u8, protocol: Protocol) -> usize {
    match protocol {
        Protocol::Abridged if first & 0x7f != 0x7f => 1,
        _ => 4,
    }
}

/// Returns `(header length, payload length)`, or `None` for a partial header.
/// Quick-ack request bits remain in the forwarded header but do not contribute
/// to its length. A malformed packet terminates the connection rather than
/// switching to unbounded buffering or treating following bytes as a new packet.
pub fn packet_length(header: &[u8], protocol: Protocol) -> io::Result<Option<(usize, usize)>> {
    let Some(&first) = header.first() else {
        return Ok(None);
    };
    let header_size = header_len(first, protocol);
    if header.len() < header_size {
        return Ok(None);
    }
    let payload = match protocol {
        Protocol::Abridged if header_size == 1 => usize::from(first & 0x7f) * 4,
        Protocol::Abridged => {
            (usize::from(header[1]) | usize::from(header[2]) << 8 | usize::from(header[3]) << 16)
                * 4
        }
        _ => {
            (u32::from_le_bytes([header[0], header[1], header[2], header[3]]) & 0x7fff_ffff)
                as usize
        }
    };
    if payload == 0 || payload > MAX_PACKET_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MTProto packet length",
        ));
    }
    Ok(Some((header_size, payload)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abridged_short_extended_and_quick_ack() {
        for (header, expected) in [
            (vec![1], (1, 4)),
            (vec![0x84], (1, 16)),
            (vec![126], (1, 504)),
            (vec![0x7f, 127, 0, 0], (4, 508)),
            (vec![0xff, 128, 0, 0], (4, 512)),
            (vec![0xff, 0, 0, 1], (4, 262144)),
        ] {
            for prefix in 0..header.len() {
                assert_eq!(
                    packet_length(&header[..prefix], Protocol::Abridged).unwrap(),
                    None
                );
            }
            assert_eq!(
                packet_length(&header, Protocol::Abridged).unwrap(),
                Some(expected)
            );
        }
    }

    #[test]
    fn intermediate_padded_lengths_allow_padding_and_ack() {
        for protocol in [Protocol::Intermediate, Protocol::PaddedIntermediate] {
            for size in [1_u32, 4, 509, 65536, MAX_PACKET_PAYLOAD as u32] {
                for ack in [0, 0x8000_0000] {
                    let header = (size | ack).to_le_bytes();
                    for prefix in 0..4 {
                        assert_eq!(packet_length(&header[..prefix], protocol).unwrap(), None);
                    }
                    assert_eq!(
                        packet_length(&header, protocol).unwrap(),
                        Some((4, size as usize))
                    );
                }
            }
        }
    }

    #[test]
    fn reject_zero_and_huge_lengths_without_allocating_packet() {
        for protocol in [
            Protocol::Abridged,
            Protocol::Intermediate,
            Protocol::PaddedIntermediate,
        ] {
            assert!(packet_length(&[0; 4], protocol).is_err());
        }
        assert!(packet_length(&[0x80], Protocol::Abridged).is_err());
        assert!(packet_length(&[0xff; 4], Protocol::Abridged).is_err());
        for protocol in [Protocol::Intermediate, Protocol::PaddedIntermediate] {
            assert!(packet_length(&0x8000_0000_u32.to_le_bytes(), protocol).is_err());
            assert!(
                packet_length(&((MAX_PACKET_PAYLOAD as u32) + 1).to_le_bytes(), protocol).is_err()
            );
            assert!(packet_length(&[0xff; 4], protocol).is_err());
        }
    }
}
