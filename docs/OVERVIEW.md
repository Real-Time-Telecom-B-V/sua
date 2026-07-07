# sua, overview

A pure-Rust **SUA** ([RFC 3868](https://www.rfc-editor.org/rfc/rfc3868.html))
codec. SUA is the **SCCP User Adaptation Layer**: it carries the SS7 SCCP user
(TCAP, and above it MAP / CAP / INAP) across an IP network, using SCTP as the
transport. This crate is the wire format, no sockets, no async runtime of its
own, so it stays portable and every consumer can unit-test against it.

## The idea

A SUA message is a fixed 8-byte **common header** followed by zero or more **TLV
parameters**, the exact same framing M3UA uses. The header carries a message
*class* (MGMT, SNM, ASPSM, ASPTM, Connectionless, Connection-Oriented, RKM) and a
*type* within that class.

Where SUA differs from M3UA is one layer up. M3UA carries the MTP3 user on a
point-code routing label (its Protocol Data parameter holds OPC/DPC/SI/SLS). SUA
carries the SCCP user, so it routes the way SCCP does: on **Global Title**, on
**SSN + Point Code**, or on Hostname / IP. A Connectionless Data Transfer
(**CLDT**) message therefore carries a **Source Address** and a **Destination
Address**, each a Routing Indicator, an Address Indicator, and Global Title /
Point Code / Subsystem Number sub-parameters, plus the SCCP-user payload in a
**Data** parameter. That CLDT is the SUA equivalent of an SCCP UDT, and the two
interwork one-for-one in a Signalling Gateway.

Two peers, a **Signalling Gateway (SG)** and one or more **Application Server
Processes (ASPs)**, run the ASPSM/ASPTM handshake (`UP` → `UP ACK`, `ACTIVE` →
`ACTIVE ACK`) before connectionless traffic may flow.

## Module map

| Module | Public surface | Role |
|---|---|---|
| `header` | `CommonHeader`, `MessageClass`, `MessageType`, `VERSION`, `SCTP_PPID` | The 8-byte common header; class/type enums with `(class, type)` mapping and validation. |
| `parameter` | `Parameter`, `tags`, `decode_parameters`, `encode_parameters`, `find_parameter` | TLV parameters: tag/length, value padded to a 4-byte boundary, and the well-known common (§3.9) and SUA-specific (§3.10) tag constants. |
| `address` | `SuaAddress`, `GlobalTitle`, `RoutingIndicator` | The Source / Destination address: Routing Indicator + Address Indicator + Global Title / Point Code / Subsystem Number sub-parameters. |
| `bcd` | `encode_gt_digits`, `decode_gt_digits` | BCD packing for the Global Title digits (explicit digit count, low nibble first). |
| `message` | `SuaMessage` | A whole message (type + parameters); typed builders (`cldt`, `cldr`, `asp_up`, `duna`, …) and accessors (`source_address`, `destination_address`, `data`, `routing_context`, `ss7_hop_count`, …). |
| `error` | `SuaError` | Typed decode/validation errors. |

## Public API surface

Re-exported at the crate root (`use sua::…`):

- **Messages**, `SuaMessage` with builders for the connectionless carriers
  (`cldt`/`cldr`), the ASPSM/ASPTM handshake, SNM (`duna`/`dava`/`daud`) and MGMT
  (`error`/`notify`); accessors for the addresses, data, routing context,
  protocol class, sequence control, SS7 hop count, SCCP cause and affected point
  codes, plus `encode` / `decode`.
- **Header**, `CommonHeader`, `MessageClass`, `MessageType`, `VERSION`,
  `SCTP_PPID`.
- **Parameters**, `Parameter` (with `from_u32` / `as_u32` / `wire_length`) and
  the `tags` module of well-known parameter tags.
- **Addresses**, `SuaAddress`, `GlobalTitle`, `RoutingIndicator`.
- **Errors**, `SuaError`.

## The SCCP-user bridge

Because a CLDT is structurally an SCCP UDT in SIGTRAN clothing, translating
between them is a mechanical mapping: called party ↔ Destination Address, calling
party ↔ Source Address, and the SCCP-user data copied straight through. The SUA
Global Title carries no encoding-scheme octet (it uses an explicit digit count
instead), so a bridge recomputes the SCCP encoding scheme from digit parity on
the way out. See [`tests/bridge.rs`](../tests/bridge.rs) for a worked,
round-trip-checked translation.

## Why it's pure

Every type here is transport-independent: encode/decode operate on byte slices.
The SCTP association (multi-streaming, the registered PPID 4, retransmission,
congestion, the SUA timers) belongs to whatever runtime owns the socket. That
separation is what keeps the codec portable and unit-testable against
RFC-derived vectors, and is what lets the exact same logic back the Rust crate
and the Python wheel.
