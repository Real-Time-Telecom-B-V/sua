# sua

[![crates.io](https://img.shields.io/crates/v/sua.svg)](https://crates.io/crates/sua)
[![docs.rs](https://docs.rs/sua/badge.svg)](https://docs.rs/sua)
[![CI](https://github.com/Real-Time-Telecom-B-V/sua/actions/workflows/ci.yaml/badge.svg)](https://github.com/Real-Time-Telecom-B-V/sua/actions/workflows/ci.yaml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A **SUA ([RFC 3868](https://www.rfc-editor.org/rfc/rfc3868.html))** codec, the
**SCCP User Adaptation Layer** that carries the SS7 SCCP user (TCAP, and above it
MAP / CAP / INAP) over IP using SCTP as the transport. SUA is the SIGTRAN sibling
of M3UA: both use the same 8-byte common header and TLV parameter framing, but
where M3UA transports the MTP3 user on a point-code routing label, SUA transports
the SCCP user with **Global Title / SSN / Point Code** addressing, exactly as
SCCP does. In a Signalling Gateway, a SUA CLDT interworks one-for-one with an
SCCP UDT.

It ships as **both** a Rust crate (`cargo add sua`) and a Rust-backed Python
wheel (`pip install sua`), built from one source tree and one version.

This crate is the **wire format** only, the common header, TLV parameters, the
GT/SSN/PC addresses, and whole-message encode/decode. It does no I/O, the SCTP
association and the running event loop belong to the composing runtime, so the
codec stays portable and every consumer can unit-test against it.

```rust
use sua::{GlobalTitle, SuaAddress, SuaMessage, MessageType};

// ASPSM handshake: build an ASP-UP, round-trip it on the wire.
let aspup = SuaMessage::asp_up(Some(1), None);
let decoded = SuaMessage::decode(&aspup.encode()).unwrap();
assert_eq!(decoded.message_type, MessageType::AspUp);

// A CLDT carrying an SCCP-user (TCAP) payload between two GT+SSN addresses.
// Digits are synthetic (fictional +1-555 range), decimal point codes.
let source = SuaAddress::with_gt(GlobalTitle::e164("15550100"), Some(8)); // MSC
let dest = SuaAddress::with_gt(GlobalTitle::e164("15550142"), Some(6));   // HLR
let cldt = SuaMessage::cldt(
    42,               // routing context
    0,                // protocol class
    &source,
    &dest,
    0,                // sequence control
    Some(15),         // SS7 hop counter
    vec![0x62, 0x40], // SCCP-user data (TCAP)
).unwrap();

let decoded = SuaMessage::decode(&cldt.encode()).unwrap();
assert_eq!(decoded.routing_context(), Some(42));
assert_eq!(decoded.destination_address().unwrap().gt_digits(), Some("15550142"));
```

```python
import sua

# ASPSM handshake message.
aspup = sua.SuaMessage.asp_up(asp_id=1)
msg = sua.decode(aspup.encode())                     # -> SuaMessage
assert msg.message_type == sua.MessageType.AspUp

# A CLDT carrying an SCCP-user payload.
source = sua.SuaAddress.with_gt(sua.GlobalTitle.e164("15550100"), ssn=8)
dest = sua.SuaAddress.with_gt(sua.GlobalTitle.e164("15550142"), ssn=6)
cldt = sua.SuaMessage.cldt(source, dest, routing_context=42, data=b"\x62\x40")
assert sua.decode(cldt.encode()).destination_address().gt_digits() == "15550142"
```

📖 More: [`docs/OVERVIEW.md`](docs/OVERVIEW.md).

## What's in the box

| Piece | Type |
|---|---|
| Common Message Header, version / reserved / class / type / length | `CommonHeader` |
| Message classes and types (MGMT / SNM / ASPSM / ASPTM / CL / CO / RKM) | `MessageClass`, `MessageType` |
| TLV parameter, tag / length / 4-byte-padded value | `Parameter`, `tags` |
| Source / Destination addresses, GT / SSN / PC sub-parameters | `SuaAddress`, `GlobalTitle`, `RoutingIndicator` |
| Whole-message encode / decode with validation | `SuaMessage` |
| Typed errors | `SuaError` |
| Constants, protocol `VERSION`, SCTP `SCTP_PPID` (4) | n/a |

## RFC 3868 coverage

| Feature | Status |
|---|---|
| Common Message Header (version 1, all message classes) | ✅ encode / decode + validation |
| Header validation, version = 1, known class + type (class 1 reserved) | ✅ rejected as `SuaError` |
| Connectionless, `CLDT` / `CLDR` with GT/SSN/PC addressing and the SCCP-user `Data` | ✅ builders + accessors |
| Addresses, Routing Indicator + Address Indicator + Global Title / Point Code / Subsystem Number | ✅ `SuaAddress` (Hostname / IP kept opaque) |
| ASPSM, `UP` / `DOWN` / `BEAT` (+ their ACKs) | ✅ builders |
| ASPTM, `ACTIVE` / `INACTIVE` (+ their ACKs) | ✅ builders |
| SNM, `DUNA` / `DAVA` / `DAUD` / `SCON` / `DUPU` / `DRST` | ✅ types; builders for DUNA/DAVA/DAUD |
| MGMT, `ERR` / `NTFY` | ✅ builders |
| Connection-Oriented, `CORE` / `COAK` / `COREF` / `RELRE` / `RELCO` / `RESCO` / `RESRE` / `CODT` / `CODA` / `COERR` / `COIT` | ✅ types + generic construction |
| RKM, `REG REQ` / `REG RSP` / `DEREG REQ` / `DEREG RSP` | ✅ types + tags |
| TLV parameters, tag/length, value padded to a 4-byte boundary | ✅ `Parameter` |
| SCTP association setup, retransmission, congestion, the PPID on the wire | ⛔ out of scope, belongs to the runtime that owns the socket |

## SUA CLDT ⇄ SCCP UDT bridge

In an STP, a SUA node interworks with an SCCP node: a SUA **CLDT** maps
one-for-one to an SCCP **UDT** and back, the calling party ↔ Source Address, the
called party ↔ Destination Address, the SCCP-user data copied through. The
addressing is structurally the same (Global Title + SSN), so the bridge is a
translation of the two party addresses plus a straight copy of the data.
[`tests/bridge.rs`](tests/bridge.rs) builds an SCCP UDT (via the `sccp` crate,
used there as a dev-dependency only), bridges it to a CLDT and back, and asserts
the global titles, subsystem numbers and user data survive the round trip. The
shipped `sua` crate links nothing SCCP.

## Validation

The wire format is checked against **Wireshark's `sua` dissector**, not just
round-trips: [`tests/wire.rs`](tests/wire.rs) places each message in an SCTP DATA
chunk (PPID 4), wraps it in a pcap, dissects it with `tshark -V`, and asserts the
message class/type and the decoded address parameters (GT digits, SSN, routing
context) with no "Malformed" / expert error. A frozen, tshark-validated CLDT hex
serves as a decode-only known-answer vector.

## Performance

Single-core, `cargo bench` ([`benches/codec.rs`](benches/codec.rs)); the codec is
allocation-light. A counting-allocator [leak check](examples/leak_check.rs)
(`./scripts/mem_leak_test.sh`) hammers encode/decode and the address path and
asserts **live bytes stay flat** (Δ 0 over millions of cycles). Both run in CI.

The Python wheel is the same Rust code behind PyO3; per-call overhead is the
Python↔Rust boundary, not the codec. The module is declared `gil_used = false`,
so it loads on free-threaded ("no-GIL") CPython 3.13t / 3.14t.

## Install

```bash
cargo add sua          # Rust crate (zero pyo3 in the default build)
pip install sua        # Rust-backed Python wheel
```

## Development

```bash
cargo test                                  # unit + integration + wire + bridge + doctests
cargo test --features python                # + the PyO3 binding face
cargo clippy --all-targets -- -D warnings
cargo bench --no-run
./scripts/mem_leak_test.sh                  # live-bytes leak check (PASS/FAIL)
cargo deny check                            # advisories, licenses, sources

# Python wheel
maturin develop --features extension-module && pytest python/tests -q
```

## License

MIT, see [LICENSE](LICENSE).
