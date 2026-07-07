use std::fmt;

use crate::address::SuaAddress;
use crate::error::SuaError;
use crate::header::{CommonHeader, MessageType};
use crate::parameter::{self, tags, Parameter};

/// The default SS7 hop counter a new CLDT starts with (RFC 3868 §3.10.1: the
/// value is decremented at each global title translation, range 15 down to 1).
pub const DEFAULT_HOP_COUNTER: u8 = 15;

/// A decoded SUA message: a message type plus its ordered TLV parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuaMessage {
    /// The message type (which implies the message class).
    pub message_type: MessageType,
    /// The message's TLV parameters, in wire order.
    pub parameters: Vec<Parameter>,
}

/// Encode a "3 reserved octets + one value octet" parameter (Protocol Class,
/// SS7 Hop Counter, Importance, Message Priority all share this shape).
fn octet_param(tag: u16, value: u8) -> Parameter {
    Parameter::new(tag, vec![0, 0, 0, value])
}

/// Read the value octet from a "3 reserved octets + one value octet" parameter.
fn read_octet_param(params: &[Parameter], tag: u16) -> Option<u8> {
    parameter::find_parameter(params, tag).and_then(|p| p.value.get(3).copied())
}

impl SuaMessage {
    /// Build a message directly from a type and a list of parameters.
    ///
    /// Prefer the typed builders (`cldt`, `asp_up`, `duna`, …) where one exists.
    pub fn new(message_type: MessageType, parameters: Vec<Parameter>) -> Self {
        Self {
            message_type,
            parameters,
        }
    }

    // ── Connectionless (CL) ──────────────────────────────────────────────────

    /// Create a CLDT (Connectionless Data Transfer), the SUA carrier for an
    /// SCCP UDT/XUDT/LUDT: it transports the SCCP-user (TCAP) `data` between two
    /// GT/SSN/PC addresses. RFC 3868 §3.2.1.
    #[allow(clippy::too_many_arguments)]
    pub fn cldt(
        routing_context: u32,
        protocol_class: u8,
        source: &SuaAddress,
        destination: &SuaAddress,
        sequence_control: u32,
        ss7_hop_count: Option<u8>,
        data: Vec<u8>,
    ) -> Result<Self, SuaError> {
        let mut params = vec![
            Parameter::from_u32(tags::ROUTING_CONTEXT, routing_context),
            octet_param(tags::PROTOCOL_CLASS, protocol_class),
            Parameter::new(tags::SOURCE_ADDRESS, source.encode()?),
            Parameter::new(tags::DESTINATION_ADDRESS, destination.encode()?),
            Parameter::from_u32(tags::SEQUENCE_CONTROL, sequence_control),
        ];
        if let Some(hop) = ss7_hop_count {
            params.push(octet_param(tags::SS7_HOP_COUNTER, hop));
        }
        params.push(Parameter::new(tags::DATA, data));
        Ok(Self::new(MessageType::Cldt, params))
    }

    /// Create a CLDR (Connectionless Data Response), the error response to a
    /// CLDT, carrying an SCCP cause. RFC 3868 §3.2.2.
    pub fn cldr(
        routing_context: u32,
        cause_type: u8,
        cause_value: u8,
        source: &SuaAddress,
        destination: &SuaAddress,
        data: Option<Vec<u8>>,
    ) -> Result<Self, SuaError> {
        let mut params = vec![
            Parameter::from_u32(tags::ROUTING_CONTEXT, routing_context),
            Parameter::new(tags::SCCP_CAUSE, vec![0, 0, cause_type, cause_value]),
            Parameter::new(tags::SOURCE_ADDRESS, source.encode()?),
            Parameter::new(tags::DESTINATION_ADDRESS, destination.encode()?),
        ];
        if let Some(d) = data {
            params.push(Parameter::new(tags::DATA, d));
        }
        Ok(Self::new(MessageType::Cldr, params))
    }

    // ── ASPSM / ASPTM handshake ──────────────────────────────────────────────

    /// Create an ASP-UP message (optionally with ASP Identifier and Info String).
    pub fn asp_up(asp_id: Option<u32>, info: Option<&str>) -> Self {
        let mut params = Vec::new();
        if let Some(id) = asp_id {
            params.push(Parameter::from_u32(tags::ASP_IDENTIFIER, id));
        }
        if let Some(s) = info {
            params.push(Parameter::new(tags::INFO_STRING, s.as_bytes().to_vec()));
        }
        Self::new(MessageType::AspUp, params)
    }

    /// Create an ASP-UP-ACK message.
    pub fn asp_up_ack(info: Option<&str>) -> Self {
        Self::info_only(MessageType::AspUpAck, info)
    }

    /// Create an ASP-DOWN message.
    pub fn asp_down(info: Option<&str>) -> Self {
        Self::info_only(MessageType::AspDown, info)
    }

    /// Create an ASP-DOWN-ACK message.
    pub fn asp_down_ack(info: Option<&str>) -> Self {
        Self::info_only(MessageType::AspDownAck, info)
    }

    fn info_only(message_type: MessageType, info: Option<&str>) -> Self {
        let mut params = Vec::new();
        if let Some(s) = info {
            params.push(Parameter::new(tags::INFO_STRING, s.as_bytes().to_vec()));
        }
        Self::new(message_type, params)
    }

    /// Create an ASP-ACTIVE message (optional traffic mode + routing context).
    pub fn asp_active(traffic_mode: Option<u32>, routing_context: Option<u32>) -> Self {
        Self::traffic_and_rc(MessageType::AspActive, traffic_mode, routing_context)
    }

    /// Create an ASP-ACTIVE-ACK message.
    pub fn asp_active_ack(traffic_mode: Option<u32>, routing_context: Option<u32>) -> Self {
        Self::traffic_and_rc(MessageType::AspActiveAck, traffic_mode, routing_context)
    }

    fn traffic_and_rc(
        message_type: MessageType,
        traffic_mode: Option<u32>,
        routing_context: Option<u32>,
    ) -> Self {
        let mut params = Vec::new();
        if let Some(tm) = traffic_mode {
            params.push(Parameter::from_u32(tags::TRAFFIC_MODE_TYPE, tm));
        }
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        Self::new(message_type, params)
    }

    /// Create an ASP-INACTIVE message.
    pub fn asp_inactive(routing_context: Option<u32>) -> Self {
        Self::rc_only(MessageType::AspInactive, routing_context)
    }

    /// Create an ASP-INACTIVE-ACK message.
    pub fn asp_inactive_ack(routing_context: Option<u32>) -> Self {
        Self::rc_only(MessageType::AspInactiveAck, routing_context)
    }

    fn rc_only(message_type: MessageType, routing_context: Option<u32>) -> Self {
        let mut params = Vec::new();
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        Self::new(message_type, params)
    }

    /// Create a BEAT (heartbeat) message.
    pub fn heartbeat(data: Option<Vec<u8>>) -> Self {
        Self::heartbeat_like(MessageType::Heartbeat, data)
    }

    /// Create a BEAT-ACK (heartbeat ack) message.
    pub fn heartbeat_ack(data: Option<Vec<u8>>) -> Self {
        Self::heartbeat_like(MessageType::HeartbeatAck, data)
    }

    fn heartbeat_like(message_type: MessageType, data: Option<Vec<u8>>) -> Self {
        let mut params = Vec::new();
        if let Some(d) = data {
            params.push(Parameter::new(tags::HEARTBEAT_DATA, d));
        }
        Self::new(message_type, params)
    }

    // ── Management (MGMT) ────────────────────────────────────────────────────

    /// Create an ERR message.
    pub fn error(
        error_code: u32,
        routing_context: Option<u32>,
        diagnostic_info: Option<Vec<u8>>,
    ) -> Self {
        let mut params = vec![Parameter::from_u32(tags::ERROR_CODE, error_code)];
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        if let Some(di) = diagnostic_info {
            params.push(Parameter::new(tags::DIAGNOSTIC_INFO, di));
        }
        Self::new(MessageType::Error, params)
    }

    /// Create a NTFY (Notify) message.
    pub fn notify(status: u32, asp_id: Option<u32>, routing_context: Option<u32>) -> Self {
        let mut params = vec![Parameter::from_u32(tags::STATUS, status)];
        if let Some(id) = asp_id {
            params.push(Parameter::from_u32(tags::ASP_IDENTIFIER, id));
        }
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        Self::new(MessageType::Notify, params)
    }

    // ── Signalling Network Management (SNM) ──────────────────────────────────

    /// Create a DUNA (Destination Unavailable) message.
    pub fn duna(routing_context: Option<u32>, affected_pcs: &[u32]) -> Self {
        Self::snm(MessageType::Duna, routing_context, affected_pcs)
    }

    /// Create a DAVA (Destination Available) message.
    pub fn dava(routing_context: Option<u32>, affected_pcs: &[u32]) -> Self {
        Self::snm(MessageType::Dava, routing_context, affected_pcs)
    }

    /// Create a DAUD (Destination State Audit) message.
    pub fn daud(routing_context: Option<u32>, affected_pcs: &[u32]) -> Self {
        Self::snm(MessageType::Daud, routing_context, affected_pcs)
    }

    fn snm(message_type: MessageType, routing_context: Option<u32>, affected_pcs: &[u32]) -> Self {
        let mut params = Vec::new();
        if let Some(rc) = routing_context {
            params.push(Parameter::from_u32(tags::ROUTING_CONTEXT, rc));
        }
        params.push(Parameter::new(
            tags::AFFECTED_POINT_CODE,
            pack_affected_point_codes(affected_pcs),
        ));
        Self::new(message_type, params)
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    /// The Routing Context value, if present.
    pub fn routing_context(&self) -> Option<u32> {
        parameter::find_parameter(&self.parameters, tags::ROUTING_CONTEXT).and_then(|p| p.as_u32())
    }

    /// The Protocol Class octet, if present.
    pub fn protocol_class(&self) -> Option<u8> {
        read_octet_param(&self.parameters, tags::PROTOCOL_CLASS)
    }

    /// The Sequence Control value, if present.
    pub fn sequence_control(&self) -> Option<u32> {
        parameter::find_parameter(&self.parameters, tags::SEQUENCE_CONTROL).and_then(|p| p.as_u32())
    }

    /// The SS7 Hop Counter, if present.
    pub fn ss7_hop_count(&self) -> Option<u8> {
        read_octet_param(&self.parameters, tags::SS7_HOP_COUNTER)
    }

    /// The Source Address (calling party). Errors if the parameter is absent.
    pub fn source_address(&self) -> Result<SuaAddress, SuaError> {
        let p = parameter::find_parameter(&self.parameters, tags::SOURCE_ADDRESS)
            .ok_or(SuaError::MissingParameter(tags::SOURCE_ADDRESS))?;
        SuaAddress::decode(&p.value)
    }

    /// The Destination Address (called party). Errors if the parameter is absent.
    pub fn destination_address(&self) -> Result<SuaAddress, SuaError> {
        let p = parameter::find_parameter(&self.parameters, tags::DESTINATION_ADDRESS)
            .ok_or(SuaError::MissingParameter(tags::DESTINATION_ADDRESS))?;
        SuaAddress::decode(&p.value)
    }

    /// The Data (SCCP-user / TCAP) payload, if present.
    pub fn data(&self) -> Option<&[u8]> {
        parameter::find_parameter(&self.parameters, tags::DATA).map(|p| p.value.as_slice())
    }

    /// The SCCP Cause as `(cause_type, cause_value)`, if present (CLDR / COREF /
    /// RELRE / …).
    pub fn sccp_cause(&self) -> Option<(u8, u8)> {
        parameter::find_parameter(&self.parameters, tags::SCCP_CAUSE).and_then(|p| {
            match (p.value.get(2), p.value.get(3)) {
                (Some(&t), Some(&v)) => Some((t, v)),
                _ => None,
            }
        })
    }

    /// The affected point codes carried in an SNM message (DUNA/DAVA/DAUD/…),
    /// decoded from the Affected Point Code parameter (mask + 24-bit PC each).
    pub fn affected_point_codes(&self) -> Vec<u32> {
        match parameter::find_parameter(&self.parameters, tags::AFFECTED_POINT_CODE) {
            Some(p) => unpack_affected_point_codes(&p.value),
            None => Vec::new(),
        }
    }

    /// Decode a complete SUA message from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, SuaError> {
        let header = CommonHeader::decode(bytes)?;
        let param_bytes = &bytes[CommonHeader::SIZE..];
        let parameters = parameter::decode_parameters(param_bytes)?;
        Ok(Self {
            message_type: header.message_type,
            parameters,
        })
    }

    /// Encode to bytes (common header + parameters).
    pub fn encode(&self) -> Vec<u8> {
        let param_bytes = parameter::encode_parameters(&self.parameters);
        let total_len = (CommonHeader::SIZE + param_bytes.len()) as u32;
        let header = CommonHeader::new(self.message_type, total_len);

        let mut buf = Vec::with_capacity(total_len as usize);
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(&param_bytes);
        buf
    }
}

impl fmt::Display for SuaMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SUA {} [{} parameters]",
            self.message_type,
            self.parameters.len()
        )
    }
}

/// Pack point codes into the on-wire Affected Point Code value: one octet of
/// mask (0 = an exact point code) followed by a 24-bit big-endian PC, per entry
/// (RFC 3868 §3.9.18).
pub fn pack_affected_point_codes(pcs: &[u32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(pcs.len() * 4);
    for &pc in pcs {
        buf.push(0); // mask: exact point code
        buf.push((pc >> 16) as u8);
        buf.push((pc >> 8) as u8);
        buf.push(pc as u8);
    }
    buf
}

/// Unpack an Affected Point Code value (mask + 24-bit PC each) back into the
/// point codes, discarding the mask octets.
pub fn unpack_affected_point_codes(data: &[u8]) -> Vec<u32> {
    data.chunks_exact(4)
        .map(|c| u32::from_be_bytes([0, c[1], c[2], c[3]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::GlobalTitle;

    fn sample_source() -> SuaAddress {
        SuaAddress::with_gt(GlobalTitle::e164("15550100"), Some(8))
    }

    fn sample_dest() -> SuaAddress {
        SuaAddress::with_gt(GlobalTitle::e164("15550142"), Some(6))
    }

    #[test]
    fn cldt_round_trip() {
        let msg = SuaMessage::cldt(
            42,
            0,
            &sample_source(),
            &sample_dest(),
            0,
            Some(DEFAULT_HOP_COUNTER),
            vec![0x62, 0x40, 0x01],
        )
        .unwrap();
        let decoded = SuaMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.message_type, MessageType::Cldt);
        assert_eq!(decoded.routing_context(), Some(42));
        assert_eq!(decoded.protocol_class(), Some(0));
        assert_eq!(decoded.sequence_control(), Some(0));
        assert_eq!(decoded.ss7_hop_count(), Some(15));
        assert_eq!(decoded.data(), Some(&[0x62, 0x40, 0x01][..]));

        let dst = decoded.destination_address().unwrap();
        assert_eq!(dst.gt_digits(), Some("15550142"));
        assert_eq!(dst.ssn, Some(6));
        let src = decoded.source_address().unwrap();
        assert_eq!(src.gt_digits(), Some("15550100"));
        assert_eq!(decoded, msg);
    }

    #[test]
    fn cldt_without_hop_count() {
        let msg =
            SuaMessage::cldt(1, 1, &sample_source(), &sample_dest(), 5, None, vec![0xAA]).unwrap();
        assert_eq!(msg.ss7_hop_count(), None);
        assert_eq!(msg.protocol_class(), Some(1));
        assert_eq!(msg.sequence_control(), Some(5));
    }

    #[test]
    fn cldr_round_trip() {
        let msg = SuaMessage::cldr(
            7,
            0x1, // return cause
            0x3, // subsystem failure
            &sample_source(),
            &sample_dest(),
            Some(vec![0x62, 0x40]),
        )
        .unwrap();
        let decoded = SuaMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.message_type, MessageType::Cldr);
        assert_eq!(decoded.sccp_cause(), Some((0x1, 0x3)));
        assert_eq!(decoded.data(), Some(&[0x62, 0x40][..]));
    }

    #[test]
    fn aspup_round_trip() {
        let msg = SuaMessage::asp_up(Some(1), Some("node-a"));
        let encoded = msg.encode();
        let decoded = SuaMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.message_type, MessageType::AspUp);
        assert_eq!(decoded.parameters.len(), 2);
    }

    #[test]
    fn aspup_no_params_header_only() {
        let msg = SuaMessage::asp_up(None, None);
        let encoded = msg.encode();
        assert_eq!(encoded.len(), 8);
        // version 1, class 3 (ASPSM), type 1 (UP), length 8.
        assert_eq!(
            encoded,
            vec![0x01, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x08]
        );
    }

    #[test]
    fn asp_lifecycle_types() {
        assert_eq!(
            SuaMessage::asp_up(None, None).message_type,
            MessageType::AspUp
        );
        assert_eq!(
            SuaMessage::asp_active(Some(1), Some(100)).message_type,
            MessageType::AspActive
        );
        assert_eq!(
            SuaMessage::asp_inactive_ack(Some(100)).message_type,
            MessageType::AspInactiveAck
        );
    }

    #[test]
    fn heartbeat_data_survives() {
        let msg = SuaMessage::heartbeat(Some(vec![1, 2, 3, 4]));
        let decoded = SuaMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.message_type, MessageType::Heartbeat);
        let hb = parameter::find_parameter(&decoded.parameters, tags::HEARTBEAT_DATA).unwrap();
        assert_eq!(hb.value, vec![1, 2, 3, 4]);
    }

    #[test]
    fn duna_affected_point_codes() {
        let msg = SuaMessage::duna(Some(1), &[2000, 3000, 0x00AB_CDEF & 0x00FF_FFFF]);
        let decoded = SuaMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded.message_type, MessageType::Duna);
        assert_eq!(
            decoded.affected_point_codes(),
            vec![2000, 3000, 0x00AB_CDEF]
        );
    }

    #[test]
    fn error_and_notify() {
        let err = SuaMessage::error(0x04, Some(1), Some(vec![0xDE, 0xAD]));
        assert_eq!(err.message_type, MessageType::Error);
        assert_eq!(
            SuaMessage::decode(&err.encode()).unwrap().routing_context(),
            Some(1)
        );

        let status = (1u32 << 16) | 2;
        let ntfy = SuaMessage::notify(status, Some(42), Some(1));
        let decoded = SuaMessage::decode(&ntfy.encode()).unwrap();
        assert_eq!(decoded.message_type, MessageType::Notify);
        let st = parameter::find_parameter(&decoded.parameters, tags::STATUS).unwrap();
        assert_eq!(st.as_u32(), Some(status));
    }

    #[test]
    fn source_address_missing_errors() {
        let msg = SuaMessage::asp_up(None, None);
        assert!(matches!(
            msg.source_address(),
            Err(SuaError::MissingParameter(tags::SOURCE_ADDRESS))
        ));
    }

    #[test]
    fn affected_point_codes_empty_when_absent() {
        assert!(SuaMessage::asp_up(None, None)
            .affected_point_codes()
            .is_empty());
    }

    #[test]
    fn generic_new_encodes_connection_oriented() {
        // Connection-oriented types are representable via the generic constructor.
        let core = SuaMessage::new(
            MessageType::Core,
            vec![
                Parameter::from_u32(tags::ROUTING_CONTEXT, 1),
                Parameter::from_u32(tags::SOURCE_REFERENCE_NUMBER, 0xAABB),
            ],
        );
        let decoded = SuaMessage::decode(&core.encode()).unwrap();
        assert_eq!(decoded.message_type, MessageType::Core);
        assert_eq!(decoded, core);
    }

    #[test]
    fn affected_point_code_pack_unpack() {
        let pcs = [1u32, 0x00AB_CDEF, 0x00FF_FFFF];
        let packed = pack_affected_point_codes(&pcs);
        assert_eq!(packed.len(), 4 * pcs.len());
        assert_eq!(packed[0], 0); // mask
        assert_eq!(unpack_affected_point_codes(&packed), pcs);
    }

    #[test]
    fn display() {
        let msg = SuaMessage::asp_up(Some(1), None);
        assert!(format!("{msg}").contains("UP"));
    }
}
