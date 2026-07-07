//! BCD digit packing for SUA Global Title address signals (RFC 3868 §3.10.2.3,
//! coded per ITU-T Q.713 §3.4.2.3.1).
//!
//! Two digits are packed per octet, low nibble first (the first address signal
//! sits in bits 1-4 of the first octet). The Global Title sub-parameter carries
//! an explicit "Number of Digits" field, so decoding reads exactly that many
//! nibbles rather than scanning for a filler. An odd digit count is padded with
//! a `0x0` filler nibble ("All filler bits SHOULD be set to 0").

use crate::error::SuaError;

/// Encode a digit string to BCD (two digits per octet, low nibble first).
///
/// An odd digit count pads the final high nibble with `0x0`. The `*`, `#` and
/// `a`-`c` extension nibbles are supported.
///
/// Example: `"15550142"` → `[0x51, 0x55, 0x10, 0x24]`.
pub fn encode_gt_digits(digits: &str) -> Result<Vec<u8>, SuaError> {
    let nibbles: Vec<u8> = digits
        .bytes()
        .map(|b| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'*' => Ok(0x0A),
            b'#' => Ok(0x0B),
            b'a' | b'A' => Ok(0x0C),
            b'b' | b'B' => Ok(0x0D),
            b'c' | b'C' => Ok(0x0E),
            _ => Err(SuaError::InvalidBcdDigit(b)),
        })
        .collect::<Result<_, _>>()?;

    let mut bytes = Vec::with_capacity(nibbles.len().div_ceil(2));
    let mut i = 0;
    while i < nibbles.len() {
        let low = nibbles[i];
        let high = if i + 1 < nibbles.len() {
            nibbles[i + 1]
        } else {
            0x00 // filler
        };
        bytes.push((high << 4) | low);
        i += 2;
    }
    Ok(bytes)
}

/// Decode exactly `num_digits` BCD digits from `bytes` (low nibble first).
///
/// Stops after `num_digits` nibbles, ignoring any trailing filler nibble and
/// padding octets. Reads no more than the available bytes.
pub fn decode_gt_digits(bytes: &[u8], num_digits: usize) -> String {
    let mut digits = String::with_capacity(num_digits);
    for i in 0..num_digits {
        let byte = match bytes.get(i / 2) {
            Some(b) => *b,
            None => break,
        };
        let nibble = if i % 2 == 0 {
            byte & 0x0F
        } else {
            (byte >> 4) & 0x0F
        };
        digits.push(nibble_to_char(nibble));
    }
    digits
}

fn nibble_to_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        0x0A => '*',
        0x0B => '#',
        0x0C => 'a',
        0x0D => 'b',
        0x0E => 'c',
        _ => '?',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_even_digits() {
        assert_eq!(encode_gt_digits("1234").unwrap(), vec![0x21, 0x43]);
    }

    #[test]
    fn encode_odd_digits_zero_filler() {
        // Odd count: last high nibble is a 0 filler (RFC 3868 §3.10.2.3).
        assert_eq!(encode_gt_digits("12345").unwrap(), vec![0x21, 0x43, 0x05]);
    }

    #[test]
    fn encode_phone_number() {
        // "15550142" (even): low-nibble-first pairing.
        assert_eq!(
            encode_gt_digits("15550142").unwrap(),
            vec![0x51, 0x55, 0x10, 0x24]
        );
    }

    #[test]
    fn decode_reads_exact_count() {
        // 8 digits from 4 octets.
        assert_eq!(decode_gt_digits(&[0x51, 0x55, 0x10, 0x24], 8), "15550142");
        // 5 digits: the trailing filler nibble is not emitted.
        assert_eq!(decode_gt_digits(&[0x21, 0x43, 0x05], 5), "12345");
    }

    #[test]
    fn round_trip_odd_and_even() {
        for original in ["15550142", "155501", "1", "5550199"] {
            let encoded = encode_gt_digits(original).unwrap();
            let decoded = decode_gt_digits(&encoded, original.len());
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn empty() {
        assert!(encode_gt_digits("").unwrap().is_empty());
        assert_eq!(decode_gt_digits(&[], 0), "");
    }

    #[test]
    fn invalid_digit() {
        match encode_gt_digits("123x") {
            Err(SuaError::InvalidBcdDigit(b'x')) => {}
            other => panic!("expected InvalidBcdDigit, got {other:?}"),
        }
    }

    #[test]
    fn extension_nibbles_round_trip() {
        let original = "12*3#a";
        let encoded = encode_gt_digits(original).unwrap();
        assert_eq!(decode_gt_digits(&encoded, original.len()), original);
    }

    #[test]
    fn decode_stops_at_buffer_end() {
        // Asking for more digits than the buffer holds stops cleanly.
        assert_eq!(decode_gt_digits(&[0x21], 8), "12");
    }
}
