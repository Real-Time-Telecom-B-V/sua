//! SUA CLDT ⇄ SCCP UDT bridge.
//!
//! In a Signalling Gateway, a SUA node terminates the IP side and interworks with
//! an SS7 SCCP node: a SUA **CLDT** (Connectionless Data Transfer) maps one-for-one
//! to an SCCP **UDT** (Unitdata), and back. Both carry the same thing, an
//! SCCP-user (TCAP) payload addressed by Global Title + SSN, so the bridge is a
//! structural translation of the two party addresses plus a straight copy of the
//! data.
//!
//! This test builds an SCCP UDT (via the `sccp` crate, a dev-dependency here),
//! bridges it into a SUA CLDT and back, and asserts the global titles, subsystem
//! numbers and user data survive the round trip. It also drives the reverse
//! direction. `sccp` is used ONLY by this test, the shipped `sua` crate links
//! nothing SCCP.
//!
//! Synthetic data only: fictional `+1-555-01xx` global titles, test SSNs.

use sccp::{GlobalTitle as SccpGt, SccpAddress, SubsystemNumber, UnitData};
use sua::{GlobalTitle as SuaGt, MessageType, SuaAddress, SuaMessage};

// ── Address translation (the heart of the bridge) ────────────────────────────

/// Map an SCCP party address to a SUA address. Handles the GT0100 (translation
/// type + numbering plan + encoding scheme + nature of address) global title,
/// the common IR.92 / roaming shape, plus the SSN.
fn sccp_addr_to_sua(addr: &SccpAddress) -> SuaAddress {
    let ssn = addr.ssn.map(|s| s.value());
    match &addr.global_title {
        SccpGt::Gt0100 {
            translation_type,
            numbering_plan,
            nature_of_address,
            digits,
            ..
        } => {
            let gt = SuaGt::new(
                0x04, // GTI 0100
                *translation_type,
                *numbering_plan,
                *nature_of_address,
                digits.clone(),
            );
            let mut out = SuaAddress::with_gt(gt, ssn);
            if let Some(pc) = addr.point_code {
                out.point_code = Some(pc as u32);
                out.include_pc = true;
            }
            out
        }
        // Route-on-SSN with no global title.
        _ => {
            let pc = addr.point_code.map(|p| p as u32).unwrap_or(0);
            SuaAddress::with_ssn_pc(ssn.unwrap_or(0), pc)
        }
    }
}

/// Map a SUA address back to an SCCP party address (the reverse translation).
/// The SUA global title carries no encoding-scheme field, so it is recomputed
/// from digit parity per ITU-T Q.713 (1 = odd, 2 = even).
fn sua_addr_to_sccp(addr: &SuaAddress) -> SccpAddress {
    let ssn = addr.ssn.map(SubsystemNumber::from_u8);
    match &addr.global_title {
        Some(gt) => {
            let encoding_scheme = if gt.digits.chars().count() % 2 == 1 {
                1
            } else {
                2
            };
            let sccp_gt = SccpGt::Gt0100 {
                translation_type: gt.translation_type,
                numbering_plan: gt.numbering_plan,
                encoding_scheme,
                nature_of_address: gt.nature_of_address,
                digits: gt.digits.clone(),
            };
            let mut out = SccpAddress::with_gt(sccp_gt, ssn);
            if let Some(pc) = addr.point_code {
                out.point_code = Some(pc as u16);
            }
            out
        }
        None => SccpAddress::with_ssn(
            ssn.unwrap_or(SubsystemNumber::Unknown),
            addr.point_code.map(|p| p as u16),
        ),
    }
}

// ── Message-level bridge helpers ─────────────────────────────────────────────

/// Bridge an SCCP UDT into a SUA CLDT: called party → destination address,
/// calling party → source address, data copied through.
fn udt_to_cldt(udt: &UnitData, routing_context: u32) -> SuaMessage {
    let source = sccp_addr_to_sua(&udt.calling_party);
    let destination = sccp_addr_to_sua(&udt.called_party);
    SuaMessage::cldt(
        routing_context,
        udt.protocol_class,
        &source,
        &destination,
        0,
        Some(sua::DEFAULT_HOP_COUNTER),
        udt.data.clone(),
    )
    .expect("build cldt")
}

/// Bridge a SUA CLDT back into an SCCP UDT: destination address → called party,
/// source address → calling party, data copied through.
fn cldt_to_udt(cldt: &SuaMessage) -> UnitData {
    let called = sua_addr_to_sccp(&cldt.destination_address().expect("destination address"));
    let calling = sua_addr_to_sccp(&cldt.source_address().expect("source address"));
    let data = cldt.data().unwrap_or(&[]).to_vec();
    let mut udt = UnitData::new(called, calling, data);
    udt.protocol_class = cldt.protocol_class().unwrap_or(0);
    udt
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn sccp_gt(digits: &str) -> SccpGt {
    SccpGt::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,  // E.164
        encoding_scheme: 2, // even digit count below
        nature_of_address: 4,
        digits: digits.to_string(),
    }
}

/// An SCCP UDT: called HLR by GT +1-555-0142, calling MSC by GT +1-555-0100,
/// carrying a small TCAP-shaped payload.
fn sample_udt() -> UnitData {
    let called = SccpAddress::with_gt(sccp_gt("15550142"), Some(SubsystemNumber::Hlr));
    let calling = SccpAddress::with_gt(sccp_gt("15550100"), Some(SubsystemNumber::Msc));
    UnitData::new(
        called,
        calling,
        vec![0x62, 0x06, 0x48, 0x04, 0x00, 0x00, 0x00, 0x01],
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn udt_bridges_to_cldt_and_back() {
    let udt = sample_udt();

    // Forward: SCCP UDT → SUA CLDT.
    let cldt = udt_to_cldt(&udt, 42);
    assert_eq!(cldt.message_type, MessageType::Cldt);

    // The CLDT carries the same addresses (called → destination, calling → source).
    let dst = cldt.destination_address().unwrap();
    assert_eq!(dst.gt_digits(), Some("15550142"));
    assert_eq!(dst.ssn, Some(SubsystemNumber::Hlr.value()));
    let src = cldt.source_address().unwrap();
    assert_eq!(src.gt_digits(), Some("15550100"));
    assert_eq!(src.ssn, Some(SubsystemNumber::Msc.value()));
    assert_eq!(cldt.data(), Some(udt.data.as_slice()));

    // The CLDT survives a wire round trip.
    let cldt = SuaMessage::decode(&cldt.encode()).unwrap();

    // Reverse: SUA CLDT → SCCP UDT. The recovered UDT equals the original.
    let back = cldt_to_udt(&cldt);
    assert_eq!(back, udt, "UDT → CLDT → UDT is lossless");
}

#[test]
fn bridge_preserves_gt_ssn_and_data_semantics() {
    let udt = sample_udt();
    let back = cldt_to_udt(&udt_to_cldt(&udt, 1));

    // Global title digits, SSN and data are the load-bearing fields of the bridge.
    assert_eq!(
        back.called_party.global_title.digits(),
        udt.called_party.global_title.digits()
    );
    assert_eq!(
        back.calling_party.global_title.digits(),
        udt.calling_party.global_title.digits()
    );
    assert_eq!(back.called_party.ssn, udt.called_party.ssn);
    assert_eq!(back.calling_party.ssn, udt.calling_party.ssn);
    assert_eq!(back.data, udt.data);
}

#[test]
fn cldt_bridges_to_udt_and_back() {
    // Reverse origin: start from a SUA CLDT built natively, bridge to UDT and back.
    let source = SuaAddress::with_gt(SuaGt::e164("15550100"), Some(SubsystemNumber::Msc.value()));
    let dest = SuaAddress::with_gt(SuaGt::e164("15550142"), Some(SubsystemNumber::Hlr.value()));
    let cldt = SuaMessage::cldt(
        7,
        0,
        &source,
        &dest,
        0,
        Some(15),
        vec![0x62, 0x06, 0x48, 0x04, 1, 2, 3, 4],
    )
    .unwrap();

    let udt = cldt_to_udt(&cldt);
    assert_eq!(udt.called_party.global_title.digits(), Some("15550142"));
    assert_eq!(udt.calling_party.global_title.digits(), Some("15550100"));

    // UDT → CLDT recovers the same destination/source and data.
    let cldt2 = udt_to_cldt(&udt, 7);
    assert_eq!(
        cldt2.destination_address().unwrap().gt_digits(),
        Some("15550142")
    );
    assert_eq!(cldt2.data(), cldt.data());
}

#[test]
fn ssn_routed_udt_bridges() {
    // A route-on-SSN UDT (no global title) bridges through SSN + PC.
    let called = SccpAddress::with_ssn(SubsystemNumber::Hlr, Some(2000));
    let calling = SccpAddress::with_ssn(SubsystemNumber::Msc, Some(1000));
    let udt = UnitData::new(called, calling, vec![0xAB, 0xCD]);

    let cldt = udt_to_cldt(&udt, 1);
    let dst = cldt.destination_address().unwrap();
    assert_eq!(dst.ssn, Some(SubsystemNumber::Hlr.value()));
    assert_eq!(dst.point_code, Some(2000));

    let back = cldt_to_udt(&cldt);
    assert_eq!(back.called_party.ssn, Some(SubsystemNumber::Hlr));
    assert_eq!(back.called_party.point_code, Some(2000));
    assert_eq!(back.data, udt.data);
}
