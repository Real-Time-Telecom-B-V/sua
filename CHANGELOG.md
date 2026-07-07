# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [1.0.0]

First release, a SUA (RFC 3868) codec for the SS7 SIGTRAN stack, carrying the
SCCP user (TCAP) over IP with Global Title / SSN / Point Code addressing.

### Added
- **`SuaMessage`**, whole-message encode / decode with typed builders for the
  connectionless carriers (`cldt`/`cldr`), the ASPSM/ASPTM handshake
  (`asp_up`/`asp_down`/`asp_active`/`asp_inactive` and their ACKs,
  `heartbeat`/`heartbeat_ack`), SNM (`duna`/`dava`/`daud`), and MGMT
  (`error`/`notify`); accessors `source_address`, `destination_address`,
  `routing_context`, `protocol_class`, `sequence_control`, `ss7_hop_count`,
  `data`, `sccp_cause`, and `affected_point_codes`.
- **`CommonHeader`**, the 8-byte common header, with **`MessageClass`** and
  **`MessageType`** covering MGMT / SNM / ASPSM / ASPTM / Connectionless /
  Connection-Oriented / RKM and their `(class, type)` mapping + validation.
- **`SuaAddress`**, **`GlobalTitle`**, **`RoutingIndicator`**, the Source /
  Destination address with its Global Title, Point Code and Subsystem Number
  sub-parameters and the Address Indicator include-bits (Hostname / IP address
  sub-parameters preserved verbatim).
- **`Parameter`** and the **`tags`** module, TLV parameters with 4-byte-boundary
  padding and the well-known common (§3.9) and SUA-specific (§3.10) parameter tags.
- **`SuaError`**, typed decode / validation errors.
- Constants **`VERSION`** and **`SCTP_PPID`** (4).
- A Rust-backed Python wheel exposing the same codec (PyO3, abi3-py39, no-GIL).
- Unit, integration, and doctest coverage; a CLDT ⇄ SCCP UDT bridge test; and
  Wireshark (tshark) dissection known-answer vectors.

[1.0.0]: https://github.com/Real-Time-Telecom-B-V/sua/releases/tag/v1.0.0
