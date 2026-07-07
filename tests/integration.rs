//! Integration tests, SUA message encoding with known byte patterns (RFC 3868).

use sua::*;

/// ASP-UP exact wire bytes: version=1, reserved=0, class=3 (ASPSM), type=1 (UP),
/// length=8 (header only).
#[test]
fn aspup_exact_wire_bytes() {
    let bytes = SuaMessage::asp_up(None, None).encode();
    assert_eq!(bytes, vec![0x01, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x08]);
}

/// ASP-DOWN exact wire bytes (class 3, type 2).
#[test]
fn aspdn_exact_wire_bytes() {
    let bytes = SuaMessage::asp_down(None).encode();
    assert_eq!(bytes, vec![0x01, 0x00, 0x03, 0x02, 0x00, 0x00, 0x00, 0x08]);
}

/// CLDT header carries class 7 (Connectionless), type 1.
#[test]
fn cldt_header_class_and_type() {
    let source = SuaAddress::with_gt(GlobalTitle::e164("15550100"), Some(8));
    let dest = SuaAddress::with_gt(GlobalTitle::e164("15550142"), Some(6));
    let bytes = SuaMessage::cldt(1, 0, &source, &dest, 0, None, vec![0x01])
        .unwrap()
        .encode();
    assert_eq!(bytes[2], 7); // class Connectionless
    assert_eq!(bytes[3], 1); // type CLDT
}

/// A Routing Context parameter encodes as tag 0x0006, length 8, value.
#[test]
fn routing_context_parameter_wire_bytes() {
    let p = Parameter::from_u32(tags::ROUTING_CONTEXT, 42);
    let bytes = p.encode();
    // 00 06 (tag) 00 08 (length) 00 00 00 2a (value)
    assert_eq!(bytes, vec![0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x2A]);
}

/// A Global Title sub-parameter has the fixed RFC 3868 §3.10.2.3 header layout.
#[test]
fn global_title_wire_layout() {
    let gt = GlobalTitle::e164("15550142"); // 8 digits, even
    let value = gt.encode().unwrap();
    // Reserved(3) + GTI + NoDigits + TT + NP + NoA + digits(4 octets).
    assert_eq!(&value[0..3], &[0x00, 0x00, 0x00]); // reserved
    assert_eq!(value[3], 0x04); // GTI 0100
    assert_eq!(value[4], 8); // number of digits
    assert_eq!(value[5], 0x00); // translation type
    assert_eq!(value[6], 0x01); // numbering plan (E.164)
    assert_eq!(value[7], 0x04); // nature of address (international)
                                // "15550142" packed low-nibble-first.
    assert_eq!(&value[8..12], &[0x51, 0x55, 0x10, 0x24]);
}

/// The Address Indicator include-bits follow RFC 3868 §3.10.2.2 (SSN 0x1, PC
/// 0x2, GT 0x4).
#[test]
fn address_indicator_include_bits_on_the_wire() {
    let addr = SuaAddress::with_gt(GlobalTitle::e164("5550100"), Some(8));
    let value = addr.encode().unwrap();
    // Routing Indicator = 1 (route on GT).
    assert_eq!(u16::from_be_bytes([value[0], value[1]]), 1);
    // Address Indicator = GT (0x4) | SSN (0x1) = 0x0005.
    assert_eq!(u16::from_be_bytes([value[2], value[3]]), 0x0005);
}

/// SS7 Hop Counter parameter: 3 reserved octets + the counter.
#[test]
fn ss7_hop_counter_layout() {
    let source = SuaAddress::with_gt(GlobalTitle::e164("5550100"), Some(8));
    let dest = SuaAddress::with_gt(GlobalTitle::e164("5550142"), Some(6));
    let msg = SuaMessage::cldt(1, 0, &source, &dest, 0, Some(15), vec![0x01]).unwrap();
    let hop = parameter::find_parameter(&msg.parameters, tags::SS7_HOP_COUNTER).unwrap();
    assert_eq!(hop.value, vec![0x00, 0x00, 0x00, 0x0F]);
    assert_eq!(msg.ss7_hop_count(), Some(15));
}

/// DUNA affected point codes use the mask + 24-bit PC layout (RFC 3868 §3.9.18).
#[test]
fn duna_affected_point_code_layout() {
    let msg = SuaMessage::duna(Some(1), &[0x0000_07D0]); // PC 2000
    let apc = parameter::find_parameter(&msg.parameters, tags::AFFECTED_POINT_CODE).unwrap();
    // mask 0x00, then 24-bit PC 0x0007D0.
    assert_eq!(apc.value, vec![0x00, 0x00, 0x07, 0xD0]);
    let decoded = SuaMessage::decode(&msg.encode()).unwrap();
    assert_eq!(decoded.affected_point_codes(), vec![2000]);
}

/// CLDR carries an SCCP Cause (cause type + cause value), tag 0x0106.
#[test]
fn cldr_sccp_cause_layout() {
    let source = SuaAddress::with_gt(GlobalTitle::e164("5550100"), Some(8));
    let dest = SuaAddress::with_gt(GlobalTitle::e164("5550142"), Some(6));
    let msg = SuaMessage::cldr(1, 0x1, 0x3, &source, &dest, None).unwrap();
    let cause = parameter::find_parameter(&msg.parameters, tags::SCCP_CAUSE).unwrap();
    // Reserved(2) + cause type(0x1) + cause value(0x3).
    assert_eq!(cause.value, vec![0x00, 0x00, 0x01, 0x03]);
    assert_eq!(msg.sccp_cause(), Some((0x1, 0x3)));
}

/// Unknown class/type header pairs are rejected.
#[test]
fn header_rejects_unknown_class_and_type() {
    // Class 1 is reserved in SUA.
    let reserved_class = [0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x08];
    assert!(SuaMessage::decode(&reserved_class).is_err());
    // Known class (CL=7) but undefined type 9.
    let unknown_type = [0x01, 0x00, 0x07, 0x09, 0x00, 0x00, 0x00, 0x08];
    assert!(SuaMessage::decode(&unknown_type).is_err());
}

/// A truncated message errors cleanly.
#[test]
fn decode_truncated_message() {
    assert!(SuaMessage::decode(&[0x01, 0x00, 0x07]).is_err());
}

/// A parameter whose declared length is below the 4-byte minimum is rejected.
#[test]
fn parameter_invalid_length_rejected() {
    let bad = [0x00, 0x06, 0x00, 0x02];
    assert!(Parameter::decode(&bad).is_err());
}

/// `wire_length` reports the padded on-wire size.
#[test]
fn parameter_wire_length_matches_encoding() {
    let p = Parameter::new(tags::DATA, b"abc".to_vec()); // 3 → pad to 4
    assert_eq!(p.wire_length(), p.encode().len());
    assert_eq!(p.wire_length(), 8);
}

/// A full CLDT round-trips through the codec preserving every field.
#[test]
fn cldt_full_round_trip() {
    let source = SuaAddress::with_gt(GlobalTitle::e164("15550100"), Some(8));
    let dest = SuaAddress::with_ssn_pc(6, 2000);
    let msg = SuaMessage::cldt(
        0xABCD,
        1,
        &source,
        &dest,
        0x1234,
        Some(10),
        vec![0x62, 0x40],
    )
    .unwrap();
    let decoded = SuaMessage::decode(&msg.encode()).unwrap();
    assert_eq!(decoded, msg);
    assert_eq!(decoded.routing_context(), Some(0xABCD));
    assert_eq!(decoded.protocol_class(), Some(1));
    assert_eq!(decoded.sequence_control(), Some(0x1234));
    assert_eq!(decoded.ss7_hop_count(), Some(10));
    let d = decoded.destination_address().unwrap();
    assert_eq!(d.point_code, Some(2000));
    assert_eq!(d.ssn, Some(6));
    assert_eq!(d.routing_indicator, RoutingIndicator::RouteOnSsnAndPc);
}
