//! Wire known-answer tests: dissect genuinely-assembled SUA messages with
//! Wireshark's `sua` dissector and assert it reads back the message class/type
//! and the decoded address parameters (GT digits, SSN, routing context) with no
//! "Malformed" / "Expert … Error".
//!
//! Each SUA message is placed in an SCTP DATA chunk with PPID 4 (SUA), wrapped
//! in a minimal Ethernet/IPv4/SCTP frame, written to a pcap, and dissected with
//! `tshark -r f.pcap -V`. Wireshark is an independent oracle: it validates the
//! byte layout the way a peer STP would, not by re-parsing our own output.
//!
//! If tshark is not installed the tests print a SKIP and pass. All data is
//! synthetic: fictional `+1-555-01xx` global titles, decimal point codes, test
//! SSNs (MAP/HLR/MSC).

use std::io::Write as _;
use std::process::Command;

use sua::{GlobalTitle, SuaAddress, SuaMessage, SCTP_PPID};

// ── pcap builder (hand-rolled Ethernet / IPv4 / SCTP framing for tshark) ──────

/// Build one SCTP packet (common header + a single DATA chunk) around `payload`.
fn sctp_packet(payload: &[u8], ppid: u32, stream: u16, tsn: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&2905u16.to_be_bytes()); // src port
    p.extend_from_slice(&2905u16.to_be_bytes()); // dst port
    p.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // verification tag
    p.extend_from_slice(&0u32.to_be_bytes()); // checksum (0, tshark does not verify)

    let mut chunk = Vec::new();
    chunk.push(0x00); // DATA
    chunk.push(0x03); // B|E
    let data_len = 16 + payload.len();
    chunk.extend_from_slice(&(data_len as u16).to_be_bytes());
    chunk.extend_from_slice(&tsn.to_be_bytes());
    chunk.extend_from_slice(&stream.to_be_bytes());
    chunk.extend_from_slice(&0u16.to_be_bytes()); // stream seq
    chunk.extend_from_slice(&ppid.to_be_bytes());
    chunk.extend_from_slice(payload);
    while chunk.len() % 4 != 0 {
        chunk.push(0);
    }
    p.extend_from_slice(&chunk);
    p
}

fn eth_ipv4_sctp(sctp: &[u8]) -> Vec<u8> {
    let total_len = 20 + sctp.len();
    let mut ip = Vec::new();
    ip.push(0x45);
    ip.push(0x00);
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes());
    ip.push(64);
    ip.push(132); // SCTP
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&[127, 0, 0, 1]);
    ip.extend_from_slice(&[127, 0, 0, 1]);
    ip.extend_from_slice(sctp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    eth
}

fn write_pcap(path: &std::path::Path, frames: &[Vec<u8>]) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    f.write_all(&0xa1b2c3d4u32.to_ne_bytes())?;
    f.write_all(&2u16.to_ne_bytes())?;
    f.write_all(&4u16.to_ne_bytes())?;
    f.write_all(&0i32.to_ne_bytes())?;
    f.write_all(&0u32.to_ne_bytes())?;
    f.write_all(&262144u32.to_ne_bytes())?;
    f.write_all(&1u32.to_ne_bytes())?; // LINKTYPE_ETHERNET
    for (i, frame) in frames.iter().enumerate() {
        f.write_all(&(i as u32).to_ne_bytes())?;
        f.write_all(&0u32.to_ne_bytes())?;
        f.write_all(&(frame.len() as u32).to_ne_bytes())?;
        f.write_all(&(frame.len() as u32).to_ne_bytes())?;
        f.write_all(frame)?;
    }
    Ok(())
}

fn tshark_available() -> bool {
    Command::new("tshark")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Dissect the SUA payloads with `tshark -V` and return the verbose text.
fn tshark_dissect(payloads: &[Vec<u8>]) -> String {
    let eth: Vec<Vec<u8>> = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| eth_ipv4_sctp(&sctp_packet(p, SCTP_PPID, 1, i as u32 + 1)))
        .collect();
    // Unique per call: the wire tests run in parallel in one process, so a shared
    // path would race.
    static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("sua_wire_{}_{}.pcap", std::process::id(), n));
    write_pcap(&path, &eth).expect("write pcap");

    let out = Command::new("tshark")
        .args(["-r", path.to_str().unwrap(), "-V"])
        .output()
        .expect("run tshark -V");
    let _ = std::fs::remove_file(&path);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Lines a clean dissection must never contain.
fn dissection_errors(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| {
            let ll = l.to_ascii_lowercase();
            ll.contains("malformed")
                || ll.contains("[expert info") && (ll.contains("error") || ll.contains("warn"))
                || ll.contains("beyond the end")
                || ll.contains("dissector bug")
        })
        .map(|l| l.trim().to_string())
        .collect()
}

// ── The CLDT under test (source it once, reuse across the tests) ──────────────

/// Build a CLDT with GT+SSN source/destination addresses, a routing context, a
/// protocol class, a sequence control, an SS7 hop count and a small TCAP-shaped
/// payload. The called party is +1-555-0142 SSN 6 (HLR); the calling party is
/// +1-555-0100 SSN 8 (MSC).
fn sample_cldt() -> SuaMessage {
    let source = SuaAddress::with_gt(GlobalTitle::e164("15550100"), Some(8));
    let dest = SuaAddress::with_gt(GlobalTitle::e164("15550142"), Some(6));
    // A minimal, well-formed TCAP Begin carrying only an originating transaction
    // id and no components, so the SUA "Data" dissects cleanly as TCAP without a
    // MAP sub-dissection of a synthetic argument.
    let tcap = vec![0x62, 0x06, 0x48, 0x04, 0x00, 0x00, 0x00, 0x01];
    SuaMessage::cldt(42, 0, &source, &dest, 0, Some(15), tcap).expect("build cldt")
}

#[test]
fn cldt_dissects_clean_in_tshark() {
    let cldt = sample_cldt();
    // Reverse-path sanity independent of tshark.
    let decoded = SuaMessage::decode(&cldt.encode()).unwrap();
    assert_eq!(
        decoded.destination_address().unwrap().gt_digits(),
        Some("15550142")
    );

    if !tshark_available() {
        eprintln!("SKIP cldt_dissects_clean_in_tshark: tshark not installed");
        return;
    }

    let text = tshark_dissect(&[cldt.encode()]);
    let errors = dissection_errors(&text);
    assert!(
        errors.is_empty(),
        "tshark flagged the CLDT:\n{}\n--- full dissection ---\n{}",
        errors.join("\n"),
        text
    );

    // The dissector must reach the SUA layer and read back our fields.
    let low = text.to_ascii_lowercase();
    assert!(low.contains("adaptation layer"), "no SUA layer:\n{text}");
    assert!(
        low.contains("connectionless data transfer") || low.contains("cldt"),
        "message type not CLDT:\n{text}"
    );
    // Address parameters decoded: both global titles and both SSNs.
    assert!(
        text.contains("15550142"),
        "called GT digits absent:\n{text}"
    );
    assert!(
        text.contains("15550100"),
        "calling GT digits absent:\n{text}"
    );
    // Routing context 42 read back.
    assert!(
        text.contains("Routing context: 42") || text.contains("Routing Context: 42"),
        "routing context 42 absent:\n{text}"
    );
    // The frame chain reached SUA.
    assert!(
        low.contains("frame") && low.contains("sctp"),
        "frame chain incomplete:\n{text}"
    );
}

#[test]
fn management_messages_dissect_clean_in_tshark() {
    if !tshark_available() {
        eprintln!("SKIP management_messages_dissect_clean_in_tshark: tshark not installed");
        return;
    }
    let payloads = vec![
        SuaMessage::asp_up(Some(1), Some("node-a")).encode(),
        SuaMessage::asp_active(Some(2), Some(42)).encode(),
        SuaMessage::heartbeat(Some(vec![0xDE, 0xAD, 0xBE, 0xEF])).encode(),
        SuaMessage::duna(Some(42), &[2000, 3000]).encode(),
        SuaMessage::notify((1u32 << 16) | 2, Some(1), Some(42)).encode(),
    ];
    let text = tshark_dissect(&payloads);
    let errors = dissection_errors(&text);
    assert!(
        errors.is_empty(),
        "tshark flagged a management message:\n{}\n--- full dissection ---\n{}",
        errors.join("\n"),
        text
    );
    let low = text.to_ascii_lowercase();
    assert!(low.contains("adaptation layer"), "no SUA layer:\n{text}");
}

// ── Decode-only known-answer vector ───────────────────────────────────────────
//
// The hex below is the exact on-wire CLDT produced by `sample_cldt()` and
// confirmed to dissect clean through Wireshark's SUA dissector (message type
// CLDT, both global titles, both SSNs, routing context 42). Decoding it and
// asserting the fields checks the wire layout against a frozen, oracle-validated
// vector, not a round-trip of our own encoder.

const CLDT_KAT: &str = "0100070100000074000600080000002a0115000800000000010200200001000580010010000000040800010451551000800300080000000801030020000100058001001000000004080001045155102480030008000000060116000800000000010100080000000f010b000c6206480400000001";

#[test]
fn cldt_known_answer_vector_decodes() {
    // Decode the frozen, tshark-validated vector and assert the fields, a
    // decode-only known-answer test, independent of our own encoder. The encoder
    // must still reproduce the exact same bytes, which catches any drift loudly.
    let bytes = hex::decode(CLDT_KAT).expect("valid KAT hex");

    let decoded = SuaMessage::decode(&bytes).unwrap();
    assert_eq!(decoded.message_type, sua::MessageType::Cldt);
    assert_eq!(decoded.routing_context(), Some(42));
    assert_eq!(decoded.protocol_class(), Some(0));
    assert_eq!(decoded.sequence_control(), Some(0));
    assert_eq!(decoded.ss7_hop_count(), Some(15));
    let dst = decoded.destination_address().unwrap();
    assert_eq!(dst.gt_digits(), Some("15550142"));
    assert_eq!(dst.ssn, Some(6));
    let src = decoded.source_address().unwrap();
    assert_eq!(src.gt_digits(), Some("15550100"));
    assert_eq!(src.ssn, Some(8));

    // The encoder reproduces the exact frozen bytes.
    assert_eq!(hex::encode(sample_cldt().encode()), CLDT_KAT);
}
