use std::fmt;

use crate::error::SuaError;

/// SUA protocol version (RFC 3868 §3.1.1).
pub const VERSION: u8 = 1;
/// SCTP Payload Protocol Identifier for SUA (RFC 3868 §1.5 / IANA).
pub const SCTP_PPID: u32 = 4;

/// SUA Message Classes (RFC 3868 §3.1.2).
///
/// SUA does not define class 1 (reserved), unlike M3UA, whose class 1 is the
/// Transfer class. SUA's user data rides the Connectionless / Connection-Oriented
/// classes instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageClass {
    /// SUA Management (MGMT) messages.
    Management = 0,
    /// Signalling Network Management (SNM) messages.
    Snm = 2,
    /// ASP State Maintenance (ASPSM) messages.
    Aspsm = 3,
    /// ASP Traffic Maintenance (ASPTM) messages.
    Asptm = 4,
    /// Connectionless (CL) messages, CLDT / CLDR.
    ConnectionLess = 7,
    /// Connection-Oriented (CO) messages.
    ConnectionOriented = 8,
    /// Routing Key Management (RKM) messages.
    Rkm = 9,
}

impl MessageClass {
    /// Map the raw message-class octet to a [`MessageClass`].
    ///
    /// Returns [`SuaError::InvalidMessageClass`] for an unknown value.
    pub fn from_u8(value: u8) -> Result<Self, SuaError> {
        match value {
            0 => Ok(Self::Management),
            2 => Ok(Self::Snm),
            3 => Ok(Self::Aspsm),
            4 => Ok(Self::Asptm),
            7 => Ok(Self::ConnectionLess),
            8 => Ok(Self::ConnectionOriented),
            9 => Ok(Self::Rkm),
            other => Err(SuaError::InvalidMessageClass(other)),
        }
    }
}

impl fmt::Display for MessageClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Management => write!(f, "MGMT(0)"),
            Self::Snm => write!(f, "SNM(2)"),
            Self::Aspsm => write!(f, "ASPSM(3)"),
            Self::Asptm => write!(f, "ASPTM(4)"),
            Self::ConnectionLess => write!(f, "CL(7)"),
            Self::ConnectionOriented => write!(f, "CO(8)"),
            Self::Rkm => write!(f, "RKM(9)"),
        }
    }
}

/// SUA Message Types per class (RFC 3868 §3.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    // Management (class 0)
    /// Error (ERR), MGMT.
    Error,
    /// Notify (NTFY), MGMT.
    Notify,
    // SNM (class 2)
    /// Destination Unavailable (DUNA), SNM.
    Duna,
    /// Destination Available (DAVA), SNM.
    Dava,
    /// Destination State Audit (DAUD), SNM.
    Daud,
    /// Signalling Congestion (SCON), SNM.
    Scon,
    /// Destination User Part Unavailable (DUPU), SNM.
    Dupu,
    /// Destination Restricted (DRST), SNM.
    Drst,
    // ASPSM (class 3)
    /// ASP Up (UP), ASPSM.
    AspUp,
    /// ASP Down (DOWN), ASPSM.
    AspDown,
    /// Heartbeat (BEAT), ASPSM.
    Heartbeat,
    /// ASP Up Acknowledgement (UP ACK), ASPSM.
    AspUpAck,
    /// ASP Down Acknowledgement (DOWN ACK), ASPSM.
    AspDownAck,
    /// Heartbeat Acknowledgement (BEAT ACK), ASPSM.
    HeartbeatAck,
    // ASPTM (class 4)
    /// ASP Active (ACTIVE), ASPTM.
    AspActive,
    /// ASP Inactive (INACTIVE), ASPTM.
    AspInactive,
    /// ASP Active Acknowledgement (ACTIVE ACK), ASPTM.
    AspActiveAck,
    /// ASP Inactive Acknowledgement (INACTIVE ACK), ASPTM.
    AspInactiveAck,
    // Connectionless (class 7)
    /// Connectionless Data Transfer (CLDT), carries an SCCP-user (TCAP) message.
    Cldt,
    /// Connectionless Data Response (CLDR), error response to a CLDT.
    Cldr,
    // Connection-Oriented (class 8)
    /// Connection Request (CORE), CO.
    Core,
    /// Connection Acknowledge (COAK), CO.
    Coak,
    /// Connection Refused (COREF), CO.
    Coref,
    /// Release Request (RELRE), CO.
    Relre,
    /// Release Complete (RELCO), CO.
    Relco,
    /// Reset Confirm (RESCO), CO.
    Resco,
    /// Reset Request (RESRE), CO.
    Resre,
    /// Connection Oriented Data Transfer (CODT), CO.
    Codt,
    /// Connection Oriented Data Acknowledge (CODA), CO.
    Coda,
    /// Connection Oriented Error (COERR), CO.
    Coerr,
    /// Connection Oriented Inactivity Test (COIT), CO.
    Coit,
    // RKM (class 9)
    /// Registration Request (REG REQ), RKM.
    RegReq,
    /// Registration Response (REG RSP), RKM.
    RegRsp,
    /// Deregistration Request (DEREG REQ), RKM.
    DeregReq,
    /// Deregistration Response (DEREG RSP), RKM.
    DeregRsp,
}

impl MessageType {
    /// Get the `(class, type)` header octet pair for this message type.
    pub fn class_and_type(&self) -> (u8, u8) {
        match self {
            Self::Error => (0, 0),
            Self::Notify => (0, 1),
            Self::Duna => (2, 1),
            Self::Dava => (2, 2),
            Self::Daud => (2, 3),
            Self::Scon => (2, 4),
            Self::Dupu => (2, 5),
            Self::Drst => (2, 6),
            Self::AspUp => (3, 1),
            Self::AspDown => (3, 2),
            Self::Heartbeat => (3, 3),
            Self::AspUpAck => (3, 4),
            Self::AspDownAck => (3, 5),
            Self::HeartbeatAck => (3, 6),
            Self::AspActive => (4, 1),
            Self::AspInactive => (4, 2),
            Self::AspActiveAck => (4, 3),
            Self::AspInactiveAck => (4, 4),
            Self::Cldt => (7, 1),
            Self::Cldr => (7, 2),
            Self::Core => (8, 1),
            Self::Coak => (8, 2),
            Self::Coref => (8, 3),
            Self::Relre => (8, 4),
            Self::Relco => (8, 5),
            Self::Resco => (8, 6),
            Self::Resre => (8, 7),
            Self::Codt => (8, 8),
            Self::Coda => (8, 9),
            Self::Coerr => (8, 10),
            Self::Coit => (8, 11),
            Self::RegReq => (9, 1),
            Self::RegRsp => (9, 2),
            Self::DeregReq => (9, 3),
            Self::DeregRsp => (9, 4),
        }
    }

    /// Map a raw `(class, type)` header pair to a [`MessageType`].
    ///
    /// Returns [`SuaError::InvalidMessageType`] for an unknown pair.
    pub fn from_class_type(class: u8, msg_type: u8) -> Result<Self, SuaError> {
        match (class, msg_type) {
            (0, 0) => Ok(Self::Error),
            (0, 1) => Ok(Self::Notify),
            (2, 1) => Ok(Self::Duna),
            (2, 2) => Ok(Self::Dava),
            (2, 3) => Ok(Self::Daud),
            (2, 4) => Ok(Self::Scon),
            (2, 5) => Ok(Self::Dupu),
            (2, 6) => Ok(Self::Drst),
            (3, 1) => Ok(Self::AspUp),
            (3, 2) => Ok(Self::AspDown),
            (3, 3) => Ok(Self::Heartbeat),
            (3, 4) => Ok(Self::AspUpAck),
            (3, 5) => Ok(Self::AspDownAck),
            (3, 6) => Ok(Self::HeartbeatAck),
            (4, 1) => Ok(Self::AspActive),
            (4, 2) => Ok(Self::AspInactive),
            (4, 3) => Ok(Self::AspActiveAck),
            (4, 4) => Ok(Self::AspInactiveAck),
            (7, 1) => Ok(Self::Cldt),
            (7, 2) => Ok(Self::Cldr),
            (8, 1) => Ok(Self::Core),
            (8, 2) => Ok(Self::Coak),
            (8, 3) => Ok(Self::Coref),
            (8, 4) => Ok(Self::Relre),
            (8, 5) => Ok(Self::Relco),
            (8, 6) => Ok(Self::Resco),
            (8, 7) => Ok(Self::Resre),
            (8, 8) => Ok(Self::Codt),
            (8, 9) => Ok(Self::Coda),
            (8, 10) => Ok(Self::Coerr),
            (8, 11) => Ok(Self::Coit),
            (9, 1) => Ok(Self::RegReq),
            (9, 2) => Ok(Self::RegRsp),
            (9, 3) => Ok(Self::DeregReq),
            (9, 4) => Ok(Self::DeregRsp),
            _ => Err(SuaError::InvalidMessageType { class, msg_type }),
        }
    }

    /// The [`MessageClass`] this type belongs to.
    pub fn message_class(&self) -> MessageClass {
        let (class, _) = self.class_and_type();
        // Every variant maps to a class this enum defines.
        MessageClass::from_u8(class).unwrap_or(MessageClass::Management)
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Error => "ERR",
            Self::Notify => "NTFY",
            Self::Duna => "DUNA",
            Self::Dava => "DAVA",
            Self::Daud => "DAUD",
            Self::Scon => "SCON",
            Self::Dupu => "DUPU",
            Self::Drst => "DRST",
            Self::AspUp => "UP",
            Self::AspDown => "DOWN",
            Self::Heartbeat => "BEAT",
            Self::AspUpAck => "UP_ACK",
            Self::AspDownAck => "DOWN_ACK",
            Self::HeartbeatAck => "BEAT_ACK",
            Self::AspActive => "ACTIVE",
            Self::AspInactive => "INACTIVE",
            Self::AspActiveAck => "ACTIVE_ACK",
            Self::AspInactiveAck => "INACTIVE_ACK",
            Self::Cldt => "CLDT",
            Self::Cldr => "CLDR",
            Self::Core => "CORE",
            Self::Coak => "COAK",
            Self::Coref => "COREF",
            Self::Relre => "RELRE",
            Self::Relco => "RELCO",
            Self::Resco => "RESCO",
            Self::Resre => "RESRE",
            Self::Codt => "CODT",
            Self::Coda => "CODA",
            Self::Coerr => "COERR",
            Self::Coit => "COIT",
            Self::RegReq => "REG_REQ",
            Self::RegRsp => "REG_RSP",
            Self::DeregReq => "DEREG_REQ",
            Self::DeregRsp => "DEREG_RSP",
        };
        write!(f, "{name}")
    }
}

/// Common Message Header (8 bytes), shared by the whole SIGTRAN family
/// (RFC 3868 §3.1).
///
/// ```ignore
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Version    |   Reserved    | Message Class | Message Type  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Message Length                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommonHeader {
    /// Protocol version (always [`VERSION`] = 1).
    pub version: u8,
    /// The message type (which implies the message class).
    pub message_type: MessageType,
    /// Total message length in octets, including this 8-byte header.
    pub message_length: u32,
}

impl CommonHeader {
    /// Size of the common header in octets.
    pub const SIZE: usize = 8;

    /// Build a header for the given message type and total message length.
    pub fn new(message_type: MessageType, message_length: u32) -> Self {
        Self {
            version: VERSION,
            message_type,
            message_length,
        }
    }

    /// Decode a common header from the first [`SIZE`](Self::SIZE) bytes.
    ///
    /// Validates the version and the `(class, type)` pair; returns a
    /// [`SuaError`] on a short buffer, unknown version, or unknown type.
    pub fn decode(bytes: &[u8]) -> Result<Self, SuaError> {
        if bytes.len() < Self::SIZE {
            return Err(SuaError::TooShort {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        let version = bytes[0];
        if version != VERSION {
            return Err(SuaError::InvalidVersion(version));
        }

        let class = bytes[2];
        let msg_type = bytes[3];
        let message_type = MessageType::from_class_type(class, msg_type)?;

        let message_length = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        Ok(Self {
            version,
            message_type,
            message_length,
        })
    }

    /// Encode the header to its 8-byte wire representation.
    pub fn encode(&self) -> [u8; 8] {
        let (class, msg_type) = self.message_type.class_and_type();
        let len_bytes = self.message_length.to_be_bytes();
        [
            self.version,
            0, // reserved
            class,
            msg_type,
            len_bytes[0],
            len_bytes[1],
            len_bytes[2],
            len_bytes[3],
        ]
    }
}

impl fmt::Display for CommonHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SUA Header [version={}, type={}, length={}]",
            self.version, self.message_type, self.message_length
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let hdr = CommonHeader::new(MessageType::Cldt, 100);
        let encoded = hdr.encode();
        let decoded = CommonHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn header_aspup() {
        let hdr = CommonHeader::new(MessageType::AspUp, 8);
        let encoded = hdr.encode();
        assert_eq!(encoded[0], 1); // version
        assert_eq!(encoded[1], 0); // reserved
        assert_eq!(encoded[2], 3); // class ASPSM
        assert_eq!(encoded[3], 1); // type UP
    }

    #[test]
    fn cldt_class_type() {
        assert_eq!(MessageType::Cldt.class_and_type(), (7, 1));
        assert_eq!(MessageType::Cldr.class_and_type(), (7, 2));
        assert_eq!(
            MessageType::Cldt.message_class(),
            MessageClass::ConnectionLess
        );
    }

    #[test]
    fn invalid_version() {
        let bytes = [2, 0, 7, 1, 0, 0, 0, 8];
        assert!(CommonHeader::decode(&bytes).is_err());
    }

    #[test]
    fn invalid_class() {
        // Class 1 is reserved in SUA.
        let bytes = [1, 0, 1, 1, 0, 0, 0, 8];
        assert!(CommonHeader::decode(&bytes).is_err());
    }

    #[test]
    fn message_type_display() {
        assert_eq!(format!("{}", MessageType::Cldt), "CLDT");
        assert_eq!(format!("{}", MessageType::AspUp), "UP");
        assert_eq!(format!("{}", MessageType::AspActiveAck), "ACTIVE_ACK");
        assert_eq!(format!("{}", MessageType::Coit), "COIT");
    }

    #[test]
    fn message_class_round_trips() {
        for (raw, class) in [
            (0u8, MessageClass::Management),
            (2, MessageClass::Snm),
            (3, MessageClass::Aspsm),
            (4, MessageClass::Asptm),
            (7, MessageClass::ConnectionLess),
            (8, MessageClass::ConnectionOriented),
            (9, MessageClass::Rkm),
        ] {
            assert_eq!(MessageClass::from_u8(raw).unwrap(), class);
        }
        // Class 1, 5, 6 are reserved / not used.
        assert!(MessageClass::from_u8(1).is_err());
        assert!(MessageClass::from_u8(5).is_err());
    }

    #[test]
    fn every_message_type_round_trips() {
        for mt in [
            MessageType::Error,
            MessageType::Notify,
            MessageType::Duna,
            MessageType::Dava,
            MessageType::Daud,
            MessageType::Scon,
            MessageType::Dupu,
            MessageType::Drst,
            MessageType::AspUp,
            MessageType::AspDown,
            MessageType::Heartbeat,
            MessageType::AspUpAck,
            MessageType::AspDownAck,
            MessageType::HeartbeatAck,
            MessageType::AspActive,
            MessageType::AspInactive,
            MessageType::AspActiveAck,
            MessageType::AspInactiveAck,
            MessageType::Cldt,
            MessageType::Cldr,
            MessageType::Core,
            MessageType::Coak,
            MessageType::Coref,
            MessageType::Relre,
            MessageType::Relco,
            MessageType::Resco,
            MessageType::Resre,
            MessageType::Codt,
            MessageType::Coda,
            MessageType::Coerr,
            MessageType::Coit,
            MessageType::RegReq,
            MessageType::RegRsp,
            MessageType::DeregReq,
            MessageType::DeregRsp,
        ] {
            let (class, ty) = mt.class_and_type();
            assert_eq!(MessageType::from_class_type(class, ty).unwrap(), mt);
        }
        // Undefined pair within a defined class.
        assert!(MessageType::from_class_type(7, 9).is_err());
    }

    #[test]
    fn header_display() {
        let hdr = CommonHeader::new(MessageType::Cldt, 100);
        let s = format!("{hdr}");
        assert!(s.contains("CLDT"));
        assert!(s.contains("length=100"));
    }

    #[test]
    fn decode_too_short() {
        assert!(CommonHeader::decode(&[1, 0, 7]).is_err());
    }
}
