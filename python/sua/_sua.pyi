"""Type stubs for the Rust-backed ``sua._sua`` extension module."""

from __future__ import annotations

# ── Protocol constants (RFC 3868 §3.1 / §7) ──────────────────────────────────
VERSION: int
SCTP_PPID: int
DEFAULT_HOP_COUNTER: int

# ── Well-known parameter tags (RFC 3868 §3.9 / §3.10) ────────────────────────
TAG_INFO_STRING: int
TAG_ROUTING_CONTEXT: int
TAG_DIAGNOSTIC_INFO: int
TAG_HEARTBEAT_DATA: int
TAG_TRAFFIC_MODE_TYPE: int
TAG_ERROR_CODE: int
TAG_STATUS: int
TAG_ASP_IDENTIFIER: int
TAG_AFFECTED_POINT_CODE: int
TAG_CORRELATION_ID: int
TAG_SS7_HOP_COUNTER: int
TAG_SOURCE_ADDRESS: int
TAG_DESTINATION_ADDRESS: int
TAG_SCCP_CAUSE: int
TAG_DATA: int
TAG_NETWORK_APPEARANCE: int
TAG_IMPORTANCE: int
TAG_MESSAGE_PRIORITY: int
TAG_PROTOCOL_CLASS: int
TAG_SEQUENCE_CONTROL: int
TAG_GLOBAL_TITLE: int
TAG_POINT_CODE: int
TAG_SUBSYSTEM_NUMBER: int

class SuaError(Exception):
    """SUA protocol / codec error (RFC 3868)."""

class MessageType:
    """SUA message types across the classes (RFC 3868 §3.1.3).

    A PyO3 enum: members compare equal to each other, but it is not a Python
    ``enum.Enum`` (no iteration, no ``.value``).
    """

    Error: MessageType
    Notify: MessageType
    Duna: MessageType
    Dava: MessageType
    Daud: MessageType
    Scon: MessageType
    Dupu: MessageType
    Drst: MessageType
    AspUp: MessageType
    AspDown: MessageType
    Heartbeat: MessageType
    AspUpAck: MessageType
    AspDownAck: MessageType
    HeartbeatAck: MessageType
    AspActive: MessageType
    AspInactive: MessageType
    AspActiveAck: MessageType
    AspInactiveAck: MessageType
    Cldt: MessageType
    Cldr: MessageType
    Core: MessageType
    Coak: MessageType
    Coref: MessageType
    Relre: MessageType
    Relco: MessageType
    Resco: MessageType
    Resre: MessageType
    Codt: MessageType
    Coda: MessageType
    Coerr: MessageType
    Coit: MessageType
    RegReq: MessageType
    RegRsp: MessageType
    DeregReq: MessageType
    DeregRsp: MessageType
    def class_and_type(self) -> tuple[int, int]:
        """The ``(class, type)`` header octet pair for this message type."""
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class RoutingIndicator:
    """How a SUA address is routed (RFC 3868 §3.10.2.1)."""

    Reserved: RoutingIndicator
    RouteOnGlobalTitle: RoutingIndicator
    RouteOnSsnAndPc: RoutingIndicator
    RouteOnHostname: RoutingIndicator
    RouteOnSsnAndIp: RoutingIndicator
    def value(self) -> int:
        """The raw 16-bit routing-indicator value."""
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class GlobalTitle:
    """A SUA Global Title (RFC 3868 §3.10.2.3)."""

    gti: int
    translation_type: int
    numbering_plan: int
    nature_of_address: int
    digits: str
    def __init__(
        self,
        gti: int,
        translation_type: int,
        numbering_plan: int,
        nature_of_address: int,
        digits: str,
    ) -> None: ...
    @staticmethod
    def e164(digits: str) -> GlobalTitle:
        """A GTI=4 international E.164 Global Title (tt=0, np=1, noa=4)."""

class SuaAddress:
    """A SUA Source / Destination Address (GT / PC / SSN + Routing Indicator)."""

    @staticmethod
    def with_gt(global_title: GlobalTitle, ssn: int | None = ...) -> SuaAddress: ...
    @staticmethod
    def with_ssn_pc(ssn: int, point_code: int) -> SuaAddress: ...
    @property
    def routing_indicator(self) -> RoutingIndicator: ...
    @property
    def global_title(self) -> GlobalTitle | None: ...
    @property
    def point_code(self) -> int | None: ...
    @property
    def ssn(self) -> int | None: ...
    @property
    def include_gt(self) -> bool: ...
    @property
    def include_pc(self) -> bool: ...
    @property
    def include_ssn(self) -> bool: ...
    def gt_digits(self) -> str | None: ...
    def address_indicator(self) -> int: ...
    def encode(self) -> bytes: ...

class SuaMessage:
    """A complete SUA message. Build one with a typed constructor, ``encode()``
    for the wire form, and :func:`decode` to parse bytes back."""

    @property
    def message_type(self) -> MessageType: ...
    @staticmethod
    def cldt(
        source: SuaAddress,
        destination: SuaAddress,
        *,
        routing_context: int,
        protocol_class: int = ...,
        sequence_control: int = ...,
        ss7_hop_count: int | None = ...,
        data: bytes = ...,
    ) -> SuaMessage: ...
    @staticmethod
    def cldr(
        source: SuaAddress,
        destination: SuaAddress,
        *,
        routing_context: int,
        cause_type: int,
        cause_value: int,
        data: bytes | None = ...,
    ) -> SuaMessage: ...
    @staticmethod
    def asp_up(asp_id: int | None = ..., info: str | None = ...) -> SuaMessage: ...
    @staticmethod
    def asp_up_ack(info: str | None = ...) -> SuaMessage: ...
    @staticmethod
    def asp_down(info: str | None = ...) -> SuaMessage: ...
    @staticmethod
    def asp_down_ack(info: str | None = ...) -> SuaMessage: ...
    @staticmethod
    def asp_active(
        traffic_mode: int | None = ..., routing_context: int | None = ...
    ) -> SuaMessage: ...
    @staticmethod
    def asp_active_ack(
        traffic_mode: int | None = ..., routing_context: int | None = ...
    ) -> SuaMessage: ...
    @staticmethod
    def asp_inactive(routing_context: int | None = ...) -> SuaMessage: ...
    @staticmethod
    def asp_inactive_ack(routing_context: int | None = ...) -> SuaMessage: ...
    @staticmethod
    def heartbeat(data: bytes | None = ...) -> SuaMessage: ...
    @staticmethod
    def heartbeat_ack(data: bytes | None = ...) -> SuaMessage: ...
    @staticmethod
    def duna(
        affected_pcs: list[int], *, routing_context: int | None = ...
    ) -> SuaMessage: ...
    @staticmethod
    def dava(
        affected_pcs: list[int], *, routing_context: int | None = ...
    ) -> SuaMessage: ...
    @staticmethod
    def daud(
        affected_pcs: list[int], *, routing_context: int | None = ...
    ) -> SuaMessage: ...
    @staticmethod
    def error(
        error_code: int,
        *,
        routing_context: int | None = ...,
        diagnostic_info: bytes | None = ...,
    ) -> SuaMessage: ...
    @staticmethod
    def notify(
        status: int, *, asp_id: int | None = ..., routing_context: int | None = ...
    ) -> SuaMessage: ...
    def routing_context(self) -> int | None: ...
    def protocol_class(self) -> int | None: ...
    def sequence_control(self) -> int | None: ...
    def ss7_hop_count(self) -> int | None: ...
    def source_address(self) -> SuaAddress:
        """The Source Address (calling party). Raises ``SuaError`` if absent."""
    def destination_address(self) -> SuaAddress:
        """The Destination Address (called party). Raises ``SuaError`` if absent."""
    def data(self) -> bytes | None: ...
    def sccp_cause(self) -> tuple[int, int] | None: ...
    def affected_point_codes(self) -> list[int]: ...
    def parameter_tags(self) -> list[int]: ...
    def encode(self) -> bytes: ...

def decode(data: bytes) -> SuaMessage:
    """Decode a complete SUA message into a :class:`SuaMessage`."""

def pack_affected_point_codes(pcs: list[int]) -> bytes:
    """Pack point codes into the on-wire Affected Point Code value (mask + 24-bit PC each)."""

def unpack_affected_point_codes(data: bytes) -> list[int]:
    """Unpack an Affected Point Code value into point codes."""
