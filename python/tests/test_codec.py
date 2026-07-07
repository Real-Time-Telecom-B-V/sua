"""Codec parity / round-trip tests for the sua wheel.

These exercise the same Rust codec the crate ships, through the Python surface:
``encode`` must match the RFC 3868 wire form, ``decode`` must recover the type
and fields, and re-encoding must reproduce the exact bytes. Synthetic data only
(fictional +1-555 global titles, test SSNs).
"""

from __future__ import annotations

import pytest

import sua

# RFC 3868 wire form of an ASP-UP with no parameters: version 1, reserved 0,
# class 3 (ASPSM), type 1 (UP), length 8 (header only).
GOLDEN_ASPUP = bytes.fromhex("0100030100000008")

# The frozen, tshark-validated CLDT known-answer vector (see tests/wire.rs).
GOLDEN_CLDT = bytes.fromhex(
    "0100070100000074000600080000002a0115000800000000010200200001000580"
    "010010000000040800010451551000800300080000000801030020000100058001"
    "001000000004080001045155102480030008000000060116000800000000010100"
    "080000000f010b000c6206480400000001"
)


def test_constants() -> None:
    assert sua.VERSION == 1
    assert sua.SCTP_PPID == 4
    assert sua.DEFAULT_HOP_COUNTER == 15
    # A few well-known parameter tags (RFC 3868 §3.9 / §3.10).
    assert sua.TAG_ROUTING_CONTEXT == 0x0006
    assert sua.TAG_SOURCE_ADDRESS == 0x0102
    assert sua.TAG_DESTINATION_ADDRESS == 0x0103
    assert sua.TAG_DATA == 0x010B
    assert sua.TAG_GLOBAL_TITLE == 0x8001


def test_aspup_matches_golden_vector() -> None:
    msg = sua.SuaMessage.asp_up()
    assert msg.encode() == GOLDEN_ASPUP
    assert msg.message_type == sua.MessageType.AspUp


def test_message_type_class_and_type() -> None:
    assert sua.MessageType.Cldt.class_and_type() == (7, 1)
    assert sua.MessageType.Cldr.class_and_type() == (7, 2)
    assert sua.MessageType.AspUp.class_and_type() == (3, 1)
    assert sua.MessageType.Duna.class_and_type() == (2, 1)
    assert sua.MessageType.Core.class_and_type() == (8, 1)


def test_decode_golden_cldt() -> None:
    msg = sua.decode(GOLDEN_CLDT)
    assert isinstance(msg, sua.SuaMessage)
    assert msg.message_type == sua.MessageType.Cldt
    assert msg.routing_context() == 42
    assert msg.protocol_class() == 0
    assert msg.ss7_hop_count() == 15
    dst = msg.destination_address()
    assert dst.gt_digits() == "15550142"
    assert dst.ssn == 6
    src = msg.source_address()
    assert src.gt_digits() == "15550100"
    assert src.ssn == 8
    # Re-encoding reproduces the exact frozen bytes.
    assert msg.encode() == GOLDEN_CLDT


def test_cldt_build_round_trip() -> None:
    source = sua.SuaAddress.with_gt(sua.GlobalTitle.e164("15550100"), ssn=8)
    dest = sua.SuaAddress.with_gt(sua.GlobalTitle.e164("15550142"), ssn=6)
    msg = sua.SuaMessage.cldt(
        source,
        dest,
        routing_context=42,
        protocol_class=0,
        sequence_control=0,
        ss7_hop_count=15,
        data=b"\x62\x06\x48\x04\x00\x00\x00\x01",
    )
    assert msg.encode() == GOLDEN_CLDT

    decoded = sua.decode(msg.encode())
    assert decoded.message_type == sua.MessageType.Cldt
    assert decoded.data() == b"\x62\x06\x48\x04\x00\x00\x00\x01"
    assert (
        decoded.destination_address().routing_indicator
        == sua.RoutingIndicator.RouteOnGlobalTitle
    )


def test_cldr_round_trip() -> None:
    source = sua.SuaAddress.with_gt(sua.GlobalTitle.e164("15550100"), ssn=8)
    dest = sua.SuaAddress.with_gt(sua.GlobalTitle.e164("15550142"), ssn=6)
    msg = sua.SuaMessage.cldr(
        source, dest, routing_context=7, cause_type=0x1, cause_value=0x3
    )
    decoded = sua.decode(msg.encode())
    assert decoded.message_type == sua.MessageType.Cldr
    assert decoded.sccp_cause() == (0x1, 0x3)


def test_address_ssn_pc() -> None:
    addr = sua.SuaAddress.with_ssn_pc(6, 2000)
    assert addr.routing_indicator == sua.RoutingIndicator.RouteOnSsnAndPc
    assert addr.point_code == 2000
    assert addr.ssn == 6
    assert addr.global_title is None
    # Address indicator: PC (0x2) + SSN (0x1).
    assert addr.address_indicator() == 0x0003


def test_global_title_fields() -> None:
    gt = sua.GlobalTitle.e164("15550142")
    assert gt.gti == 4
    assert gt.numbering_plan == 1
    assert gt.nature_of_address == 4
    assert gt.digits == "15550142"


def test_duna_round_trip_and_affected_point_codes() -> None:
    pcs = [2000, 3000, 0x00ABCDEF]
    msg = sua.SuaMessage.duna(pcs, routing_context=42)
    decoded = sua.decode(msg.encode())
    assert decoded.message_type == sua.MessageType.Duna
    assert decoded.affected_point_codes() == pcs
    assert decoded.routing_context() == 42


@pytest.mark.parametrize(
    "builder,expected_type",
    [
        (lambda: sua.SuaMessage.asp_up_ack(), sua.MessageType.AspUpAck),
        (lambda: sua.SuaMessage.asp_down(), sua.MessageType.AspDown),
        (lambda: sua.SuaMessage.asp_active(), sua.MessageType.AspActive),
        (lambda: sua.SuaMessage.asp_inactive(), sua.MessageType.AspInactive),
        (lambda: sua.SuaMessage.heartbeat(), sua.MessageType.Heartbeat),
        (lambda: sua.SuaMessage.heartbeat_ack(), sua.MessageType.HeartbeatAck),
        (lambda: sua.SuaMessage.dava([1, 2]), sua.MessageType.Dava),
        (lambda: sua.SuaMessage.daud([3]), sua.MessageType.Daud),
        (lambda: sua.SuaMessage.error(0x01), sua.MessageType.Error),
        (lambda: sua.SuaMessage.notify(0), sua.MessageType.Notify),
    ],
)
def test_all_builders_round_trip(builder, expected_type) -> None:
    msg = builder()
    assert msg.message_type == expected_type
    wire = msg.encode()
    decoded = sua.decode(wire)
    assert decoded.message_type == expected_type
    assert decoded.encode() == wire


def test_heartbeat_data_survives() -> None:
    msg = sua.SuaMessage.heartbeat(data=b"ping-1234")
    decoded = sua.decode(msg.encode())
    assert decoded.message_type == sua.MessageType.Heartbeat
    assert sua.TAG_HEARTBEAT_DATA in decoded.parameter_tags()


def test_point_code_helpers_round_trip() -> None:
    pcs = [1, 0x00ABCDEF, 0x00FFFFFF]
    packed = sua.pack_affected_point_codes(pcs)
    assert len(packed) == 4 * len(pcs)
    assert sua.unpack_affected_point_codes(packed) == pcs


def test_source_address_missing_raises() -> None:
    msg = sua.SuaMessage.asp_up()
    with pytest.raises(sua.SuaError):
        msg.source_address()


def test_decode_rejects_truncated() -> None:
    with pytest.raises(sua.SuaError):
        sua.decode(b"\x01\x00\x07")


def test_decode_rejects_reserved_class() -> None:
    # Class 1 is reserved in SUA.
    bad = bytes.fromhex("0100010100000008")
    with pytest.raises(sua.SuaError):
        sua.decode(bad)
