use std::fmt;

use crate::error::SuaError;

/// Well-known SUA parameter tags (RFC 3868 §3.9 common, §3.10 SUA-specific).
pub mod tags {
    // ── Common parameters (RFC 3868 §3.9) ────────────────────────────────────
    /// Info String, a human-readable UTF-8 diagnostic string.
    pub const INFO_STRING: u16 = 0x0004;
    /// Routing Context, identifies the Application Server / routing key.
    pub const ROUTING_CONTEXT: u16 = 0x0006;
    /// Diagnostic Information, carried in ERR / NTFY.
    pub const DIAGNOSTIC_INFO: u16 = 0x0007;
    /// Heartbeat Data, opaque data echoed in BEAT / BEAT-ACK.
    pub const HEARTBEAT_DATA: u16 = 0x0009;
    /// Traffic Mode Type, Override / Loadshare / Broadcast.
    pub const TRAFFIC_MODE_TYPE: u16 = 0x000B;
    /// Error Code, carried in ERR.
    pub const ERROR_CODE: u16 = 0x000C;
    /// Status, status type + status information, carried in NTFY.
    pub const STATUS: u16 = 0x000D;
    /// ASP Identifier, a unique value identifying the ASP.
    pub const ASP_IDENTIFIER: u16 = 0x0011;
    /// Affected Point Code, one or more affected point codes (SNM).
    pub const AFFECTED_POINT_CODE: u16 = 0x0012;
    /// Correlation Id, correlates CLDT messages in a Broadcast AS.
    pub const CORRELATION_ID: u16 = 0x0013;
    /// Registration Result, the result of a REG-REQ.
    pub const REGISTRATION_RESULT: u16 = 0x0014;
    /// Deregistration Result, the result of a DEREG-REQ.
    pub const DEREGISTRATION_RESULT: u16 = 0x0015;
    /// Registration Status, per-routing-key status in a REG-RSP.
    pub const REGISTRATION_STATUS: u16 = 0x0016;
    /// Deregistration Status, per-routing-context status in a DEREG-RSP.
    pub const DEREGISTRATION_STATUS: u16 = 0x0017;
    /// Local Routing Key Identifier, an ASP-local routing-key handle.
    pub const LOCAL_ROUTING_KEY_ID: u16 = 0x0018;

    // ── SUA-specific parameters (RFC 3868 §3.10) ─────────────────────────────
    /// SS7 Hop Counter, decremented at each global title translation.
    pub const SS7_HOP_COUNTER: u16 = 0x0101;
    /// Source Address, the calling party (GT / PC / SSN sub-parameters).
    pub const SOURCE_ADDRESS: u16 = 0x0102;
    /// Destination Address, the called party (GT / PC / SSN sub-parameters).
    pub const DESTINATION_ADDRESS: u16 = 0x0103;
    /// Source Reference Number, connection-oriented, 4-octet integer.
    pub const SOURCE_REFERENCE_NUMBER: u16 = 0x0104;
    /// Destination Reference Number, connection-oriented, 4-octet integer.
    pub const DESTINATION_REFERENCE_NUMBER: u16 = 0x0105;
    /// SCCP Cause, cause type + cause value, carried in CLDR / COREF / …
    pub const SCCP_CAUSE: u16 = 0x0106;
    /// Sequence Number, connection-oriented sequencing.
    pub const SEQUENCE_NUMBER: u16 = 0x0107;
    /// Receive Sequence Number, connection-oriented sequencing.
    pub const RECEIVE_SEQUENCE_NUMBER: u16 = 0x0108;
    /// ASP Capabilities, advertised interworking capabilities.
    pub const ASP_CAPABILITIES: u16 = 0x0109;
    /// Credit, connection-oriented flow-control window.
    pub const CREDIT: u16 = 0x010A;
    /// Data, the SCCP-user (e.g. TCAP) payload carried by CLDT / CODT.
    pub const DATA: u16 = 0x010B;
    /// User/Cause, the unavailable user part and cause (DUPU).
    pub const USER_CAUSE: u16 = 0x010C;
    /// Network Appearance, distinguishes SS7 network contexts at the SG.
    pub const NETWORK_APPEARANCE: u16 = 0x010D;
    /// Routing Key, the routing key registered via RKM.
    pub const ROUTING_KEY: u16 = 0x010E;
    /// DRN Label, destination reference number label (segmentation).
    pub const DRN_LABEL: u16 = 0x010F;
    /// TID Label, transaction identifier label (segmentation).
    pub const TID_LABEL: u16 = 0x0110;
    /// Address Range, a range of addresses in a routing key.
    pub const ADDRESS_RANGE: u16 = 0x0111;
    /// SMI, Subsystem Multiplicity Indicator.
    pub const SMI: u16 = 0x0112;
    /// Importance, SCCP importance (0-7).
    pub const IMPORTANCE: u16 = 0x0113;
    /// Message Priority, SCCP message priority (0-3, 0xFF unspecified).
    pub const MESSAGE_PRIORITY: u16 = 0x0114;
    /// Protocol Class, SCCP protocol class + return-on-error option.
    pub const PROTOCOL_CLASS: u16 = 0x0115;
    /// Sequence Control, SLS-keyed loadshare / sequencing control.
    pub const SEQUENCE_CONTROL: u16 = 0x0116;
    /// Segmentation, first/remaining segments + segmentation reference.
    pub const SEGMENTATION: u16 = 0x0117;
    /// Congestion Level, congestion level (SCON).
    pub const CONGESTION_LEVEL: u16 = 0x0118;

    // ── Destination / Source Address sub-parameters (RFC 3868 §3.10.2) ───────
    /// Global Title sub-parameter (GTI + digits).
    pub const GLOBAL_TITLE: u16 = 0x8001;
    /// Point Code sub-parameter (32-bit point code).
    pub const POINT_CODE: u16 = 0x8002;
    /// Subsystem Number sub-parameter (1-octet SSN).
    pub const SUBSYSTEM_NUMBER: u16 = 0x8003;
    /// IPv4 Address sub-parameter.
    pub const IPV4_ADDRESS: u16 = 0x8004;
    /// Hostname sub-parameter.
    pub const HOSTNAME: u16 = 0x8005;
    /// IPv6 Address sub-parameter.
    pub const IPV6_ADDRESS: u16 = 0x8006;
}

/// A TLV (Tag-Length-Value) parameter (RFC 3868 §3.1.5).
///
/// SUA parameters are encoded as:
/// ```ignore
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Parameter Tag        |       Parameter Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                       Parameter Value                         /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Length includes the 4-byte tag+length header. Value is padded to a 4-byte
/// boundary; the padding is not counted in Length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    /// The parameter tag (see the [`tags`] module for well-known values).
    pub tag: u16,
    /// The parameter value, unpadded (padding is applied only on the wire).
    pub value: Vec<u8>,
}

impl Parameter {
    /// Build a parameter from a tag and its (unpadded) value bytes.
    pub fn new(tag: u16, value: Vec<u8>) -> Self {
        Self { tag, value }
    }

    /// Create a parameter with a 4-byte u32 value.
    pub fn from_u32(tag: u16, value: u32) -> Self {
        Self {
            tag,
            value: value.to_be_bytes().to_vec(),
        }
    }

    /// Read the value as a u32 (for 4-byte parameters).
    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() >= 4 {
            Some(u32::from_be_bytes([
                self.value[0],
                self.value[1],
                self.value[2],
                self.value[3],
            ]))
        } else {
            None
        }
    }

    /// Decode a single parameter from bytes, returning the parameter and bytes consumed.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), SuaError> {
        if bytes.len() < 4 {
            return Err(SuaError::TooShort {
                expected: 4,
                actual: bytes.len(),
            });
        }

        let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
        let length = u16::from_be_bytes([bytes[2], bytes[3]]);

        if (length as usize) < 4 {
            return Err(SuaError::InvalidParameter { tag, length });
        }

        let value_len = (length as usize) - 4;
        if bytes.len() < 4 + value_len {
            return Err(SuaError::ParameterTooShort {
                tag,
                expected: 4 + value_len,
                actual: bytes.len(),
            });
        }

        let value = bytes[4..4 + value_len].to_vec();

        // Padded length (round up to 4-byte boundary).
        let padded_len = (4 + value_len + 3) & !3;
        let consumed = padded_len.min(bytes.len());

        Ok((Self { tag, value }, consumed))
    }

    /// Encode to bytes with padding to a 4-byte boundary.
    pub fn encode(&self) -> Vec<u8> {
        let length = (4 + self.value.len()) as u16;
        let mut buf = Vec::with_capacity((4 + self.value.len() + 3) & !3);
        buf.extend_from_slice(&self.tag.to_be_bytes());
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&self.value);
        // Pad to 4-byte boundary.
        let pad = (4 - (self.value.len() % 4)) % 4;
        buf.resize(buf.len() + pad, 0u8);
        buf
    }

    /// The wire length of this parameter (including padding).
    pub fn wire_length(&self) -> usize {
        (4 + self.value.len() + 3) & !3
    }
}

impl fmt::Display for Parameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag_name = match self.tag {
            tags::INFO_STRING => "Info String",
            tags::ROUTING_CONTEXT => "Routing Context",
            tags::DIAGNOSTIC_INFO => "Diagnostic Info",
            tags::HEARTBEAT_DATA => "Heartbeat Data",
            tags::TRAFFIC_MODE_TYPE => "Traffic Mode Type",
            tags::ERROR_CODE => "Error Code",
            tags::STATUS => "Status",
            tags::ASP_IDENTIFIER => "ASP Identifier",
            tags::AFFECTED_POINT_CODE => "Affected Point Code",
            tags::CORRELATION_ID => "Correlation ID",
            tags::SS7_HOP_COUNTER => "SS7 Hop Counter",
            tags::SOURCE_ADDRESS => "Source Address",
            tags::DESTINATION_ADDRESS => "Destination Address",
            tags::SCCP_CAUSE => "SCCP Cause",
            tags::DATA => "Data",
            tags::NETWORK_APPEARANCE => "Network Appearance",
            tags::IMPORTANCE => "Importance",
            tags::MESSAGE_PRIORITY => "Message Priority",
            tags::PROTOCOL_CLASS => "Protocol Class",
            tags::SEQUENCE_CONTROL => "Sequence Control",
            tags::GLOBAL_TITLE => "Global Title",
            tags::POINT_CODE => "Point Code",
            tags::SUBSYSTEM_NUMBER => "Subsystem Number",
            _ => "Unknown",
        };
        write!(
            f,
            "Parameter [tag=0x{:04x} ({}), len={}]",
            self.tag,
            tag_name,
            self.value.len()
        )
    }
}

/// Decode all parameters from a byte slice.
pub fn decode_parameters(bytes: &[u8]) -> Result<Vec<Parameter>, SuaError> {
    let mut params = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            break; // Not enough for another parameter header.
        }
        let (param, consumed) = Parameter::decode(&bytes[offset..])?;
        params.push(param);
        offset += consumed;
    }

    Ok(params)
}

/// Find a parameter by tag in a list.
pub fn find_parameter(params: &[Parameter], tag: u16) -> Option<&Parameter> {
    params.iter().find(|p| p.tag == tag)
}

/// Encode a list of parameters to bytes.
pub fn encode_parameters(params: &[Parameter]) -> Vec<u8> {
    let mut buf = Vec::new();
    for param in params {
        buf.extend_from_slice(&param.encode());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_round_trip() {
        let param = Parameter::new(tags::ROUTING_CONTEXT, vec![0, 0, 0, 1]);
        let encoded = param.encode();
        let (decoded, consumed) = Parameter::decode(&encoded).unwrap();
        assert_eq!(decoded, param);
        assert_eq!(consumed, 8); // 4 header + 4 value, no padding needed.
    }

    #[test]
    fn parameter_padding() {
        // Value with 3 bytes needs 1 byte padding.
        let param = Parameter::new(tags::DATA, vec![1, 2, 3]);
        let encoded = param.encode();
        assert_eq!(encoded.len(), 8); // 4 header + 3 value + 1 padding.
        assert_eq!(encoded[7], 0); // padding byte.
                                   // Length field excludes the padding.
        assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]), 7);
    }

    #[test]
    fn parameter_from_u32() {
        let param = Parameter::from_u32(tags::ROUTING_CONTEXT, 42);
        assert_eq!(param.as_u32(), Some(42));
    }

    #[test]
    fn multiple_parameters() {
        let params = vec![
            Parameter::from_u32(tags::ROUTING_CONTEXT, 1),
            Parameter::new(tags::INFO_STRING, b"hello".to_vec()),
        ];
        let encoded = encode_parameters(&params);
        let decoded = decode_parameters(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].tag, tags::ROUTING_CONTEXT);
        assert_eq!(decoded[1].tag, tags::INFO_STRING);
        assert_eq!(decoded[1].value, b"hello");
    }

    #[test]
    fn find_parameter_works() {
        let params = vec![
            Parameter::from_u32(tags::ROUTING_CONTEXT, 1),
            Parameter::from_u32(tags::PROTOCOL_CLASS, 2),
        ];
        let found = find_parameter(&params, tags::PROTOCOL_CLASS);
        assert!(found.is_some());
        assert_eq!(found.unwrap().as_u32(), Some(2));
        assert!(find_parameter(&params, tags::ERROR_CODE).is_none());
    }

    #[test]
    fn display() {
        let param = Parameter::from_u32(tags::SOURCE_ADDRESS, 1);
        let s = format!("{param}");
        assert!(s.contains("Source Address"));
        assert!(s.contains("0x0102"));
    }

    #[test]
    fn sub_parameter_tags_have_high_bit() {
        // The address sub-parameter tags all carry the high bit (0x8000).
        assert_eq!(tags::GLOBAL_TITLE, 0x8001);
        assert_eq!(tags::POINT_CODE, 0x8002);
        assert_eq!(tags::SUBSYSTEM_NUMBER, 0x8003);
    }

    #[test]
    fn as_u32_none_when_too_short() {
        let param = Parameter::new(tags::ROUTING_CONTEXT, vec![1, 2, 3]);
        assert_eq!(param.as_u32(), None);
    }

    #[test]
    fn decode_rejects_short_and_bad_length() {
        // Fewer than 4 bytes: no room for a tag+length header.
        assert!(Parameter::decode(&[0x00, 0x06]).is_err());
        // Declared length < 4 is illegal.
        assert!(Parameter::decode(&[0x00, 0x06, 0x00, 0x02]).is_err());
        // Declared length overruns the buffer.
        assert!(Parameter::decode(&[0x00, 0x06, 0x00, 0x10]).is_err());
    }

    #[test]
    fn decode_parameters_ignores_trailing_stray_bytes() {
        let mut bytes = Parameter::from_u32(tags::ROUTING_CONTEXT, 1).encode();
        bytes.extend_from_slice(&[0xAA, 0xBB]);
        let params = decode_parameters(&bytes).unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].as_u32(), Some(1));
    }
}
