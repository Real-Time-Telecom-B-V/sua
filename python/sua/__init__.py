"""sua, Rust-backed SUA (RFC 3868) codec for Python.

SUA (SCCP User Adaptation Layer) carries the SS7 SCCP user, TCAP, and above it
MAP / CAP / INAP, over SCTP, so an SS7 network can ride IP the way it would ride
TDM. It is the SIGTRAN sibling of M3UA: same common header and TLV framing, but
SUA routes the SCCP user on Global Title / SSN / Point Code addressing, exactly
as SCCP does. In a Signalling Gateway a SUA CLDT interworks one-for-one with an
SCCP UDT.

This package exposes the same codec the Rust crate (``cargo add sua``) ships,
from one source tree / one version. The wire work (common-header pack/unpack, TLV
parameters, the GT/SSN/PC address copy) runs in Rust; Python just builds and
inspects messages.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._sua import (
    DEFAULT_HOP_COUNTER,
    SCTP_PPID,
    TAG_AFFECTED_POINT_CODE,
    TAG_ASP_IDENTIFIER,
    TAG_CORRELATION_ID,
    TAG_DATA,
    TAG_DESTINATION_ADDRESS,
    TAG_DIAGNOSTIC_INFO,
    TAG_ERROR_CODE,
    TAG_GLOBAL_TITLE,
    TAG_HEARTBEAT_DATA,
    TAG_IMPORTANCE,
    TAG_INFO_STRING,
    TAG_MESSAGE_PRIORITY,
    TAG_NETWORK_APPEARANCE,
    TAG_POINT_CODE,
    TAG_PROTOCOL_CLASS,
    TAG_ROUTING_CONTEXT,
    TAG_SCCP_CAUSE,
    TAG_SEQUENCE_CONTROL,
    TAG_SOURCE_ADDRESS,
    TAG_SS7_HOP_COUNTER,
    TAG_STATUS,
    TAG_SUBSYSTEM_NUMBER,
    TAG_TRAFFIC_MODE_TYPE,
    VERSION,
    GlobalTitle,
    MessageType,
    RoutingIndicator,
    SuaAddress,
    SuaError,
    SuaMessage,
    decode,
    pack_affected_point_codes,
    unpack_affected_point_codes,
)

try:
    __version__ = version("sua")
except PackageNotFoundError:  # running from a source checkout without an installed dist
    __version__ = "0.0.0+unknown"

__all__ = [
    # messages + codec
    "SuaMessage",
    "decode",
    "SuaError",
    # addresses
    "SuaAddress",
    "GlobalTitle",
    # enums
    "MessageType",
    "RoutingIndicator",
    # point-code helpers
    "pack_affected_point_codes",
    "unpack_affected_point_codes",
    # protocol constants
    "VERSION",
    "SCTP_PPID",
    "DEFAULT_HOP_COUNTER",
    # parameter tags
    "TAG_INFO_STRING",
    "TAG_ROUTING_CONTEXT",
    "TAG_DIAGNOSTIC_INFO",
    "TAG_HEARTBEAT_DATA",
    "TAG_TRAFFIC_MODE_TYPE",
    "TAG_ERROR_CODE",
    "TAG_STATUS",
    "TAG_ASP_IDENTIFIER",
    "TAG_AFFECTED_POINT_CODE",
    "TAG_CORRELATION_ID",
    "TAG_SS7_HOP_COUNTER",
    "TAG_SOURCE_ADDRESS",
    "TAG_DESTINATION_ADDRESS",
    "TAG_SCCP_CAUSE",
    "TAG_DATA",
    "TAG_NETWORK_APPEARANCE",
    "TAG_IMPORTANCE",
    "TAG_MESSAGE_PRIORITY",
    "TAG_PROTOCOL_CLASS",
    "TAG_SEQUENCE_CONTROL",
    "TAG_GLOBAL_TITLE",
    "TAG_POINT_CODE",
    "TAG_SUBSYSTEM_NUMBER",
    "__version__",
]
