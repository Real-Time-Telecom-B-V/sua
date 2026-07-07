//! SUA Source / Destination Address ([`SuaAddress`]) and its Global Title,
//! Point Code and Subsystem Number sub-parameters (RFC 3868 §3.10.2).
//!
//! An address parameter carries a 16-bit Routing Indicator and a 16-bit Address
//! Indicator, followed by TLV sub-parameters (Global Title 0x8001, Point Code
//! 0x8002, Subsystem Number 0x8003, and, kept opaque here, Hostname / IP
//! addresses). This is where SUA differs from M3UA: M3UA routes on a point-code
//! routing label (Protocol Data), whereas SUA routes the SCCP user on GT / SSN /
//! PC, exactly as SCCP does.

use std::fmt;

use crate::bcd;
use crate::error::SuaError;
use crate::parameter::{self, tags, Parameter};

/// Routing Indicator values (RFC 3868 §3.10.2.1), how the address is routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RoutingIndicator {
    /// Reserved (0).
    Reserved = 0,
    /// Route on Global Title (1).
    RouteOnGlobalTitle = 1,
    /// Route on Subsystem Number + Point Code (2).
    RouteOnSsnAndPc = 2,
    /// Route on Hostname (3).
    RouteOnHostname = 3,
    /// Route on Subsystem Number + IP Address (4).
    RouteOnSsnAndIp = 4,
}

impl RoutingIndicator {
    /// Map the raw 16-bit routing-indicator field to a [`RoutingIndicator`].
    ///
    /// Returns [`SuaError::InvalidRoutingIndicator`] for a value above 4.
    pub fn from_u16(value: u16) -> Result<Self, SuaError> {
        match value {
            0 => Ok(Self::Reserved),
            1 => Ok(Self::RouteOnGlobalTitle),
            2 => Ok(Self::RouteOnSsnAndPc),
            3 => Ok(Self::RouteOnHostname),
            4 => Ok(Self::RouteOnSsnAndIp),
            other => Err(SuaError::InvalidRoutingIndicator(other)),
        }
    }

    /// The raw 16-bit routing-indicator value.
    pub fn value(self) -> u16 {
        self as u16
    }
}

impl fmt::Display for RoutingIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reserved => write!(f, "Reserved(0)"),
            Self::RouteOnGlobalTitle => write!(f, "GT(1)"),
            Self::RouteOnSsnAndPc => write!(f, "SSN+PC(2)"),
            Self::RouteOnHostname => write!(f, "Hostname(3)"),
            Self::RouteOnSsnAndIp => write!(f, "SSN+IP(4)"),
        }
    }
}

/// A SUA Global Title sub-parameter (tag `0x8001`, RFC 3868 §3.10.2.3).
///
/// Unlike SCCP, whose Global Title layout varies by indicator, the SUA sub-
/// parameter is a fixed shape: 3 reserved octets, the GTI, the digit count, then
/// translation type / numbering plan / nature of address, then the BCD digits.
/// The four descriptor octets are always present; the GTI states which are
/// meaningful.
///
/// ```ignore
/// |                Reserved                       |      GTI      |
/// |   No. Digits  | Trans. type   |    Num. Plan  | Nature of Add |
/// /                     Global Title Digits (BCD)                 /
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalTitle {
    /// Global Title Indicator (Q.713 §3.4.2.3): 0-4.
    pub gti: u8,
    /// Translation type.
    pub translation_type: u8,
    /// Numbering plan (e.g. 1 = ISDN/E.164).
    pub numbering_plan: u8,
    /// Nature of address (e.g. 4 = international number).
    pub nature_of_address: u8,
    /// The address digits (decoded from BCD).
    pub digits: String,
}

impl GlobalTitle {
    /// Fixed descriptor size before the digits: 3 reserved + GTI + count + TT +
    /// NP + NoA.
    pub const HEADER_SIZE: usize = 8;

    /// Build a Global Title from its indicator, descriptors and digit string.
    pub fn new(
        gti: u8,
        translation_type: u8,
        numbering_plan: u8,
        nature_of_address: u8,
        digits: impl Into<String>,
    ) -> Self {
        Self {
            gti,
            translation_type,
            numbering_plan,
            nature_of_address,
            digits: digits.into(),
        }
    }

    /// A GTI=4 international E.164 Global Title (translation type 0, numbering
    /// plan 1, nature of address 4), the common IR.92 / roaming shape.
    pub fn e164(digits: impl Into<String>) -> Self {
        Self::new(0x04, 0, 1, 4, digits)
    }

    /// Decode a Global Title from a sub-parameter value (after tag+length).
    pub fn decode(value: &[u8]) -> Result<Self, SuaError> {
        if value.len() < Self::HEADER_SIZE {
            return Err(SuaError::TooShort {
                expected: Self::HEADER_SIZE,
                actual: value.len(),
            });
        }
        // value[0..3] reserved.
        let gti = value[3];
        let num_digits = value[4] as usize;
        let translation_type = value[5];
        let numbering_plan = value[6];
        let nature_of_address = value[7];
        let digits = bcd::decode_gt_digits(&value[Self::HEADER_SIZE..], num_digits);
        Ok(Self {
            gti,
            translation_type,
            numbering_plan,
            nature_of_address,
            digits,
        })
    }

    /// Encode the Global Title to its sub-parameter value bytes (no TLV wrapper).
    pub fn encode(&self) -> Result<Vec<u8>, SuaError> {
        let digit_bytes = bcd::encode_gt_digits(&self.digits)?;
        let mut v = Vec::with_capacity(Self::HEADER_SIZE + digit_bytes.len());
        v.extend_from_slice(&[0, 0, 0]); // Reserved.
        v.push(self.gti);
        v.push(self.digits.chars().count() as u8);
        v.push(self.translation_type);
        v.push(self.numbering_plan);
        v.push(self.nature_of_address);
        v.extend_from_slice(&digit_bytes);
        Ok(v)
    }
}

impl fmt::Display for GlobalTitle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GT [gti={}, tt={}, np={}, noa={}, digits={}]",
            self.gti,
            self.translation_type,
            self.numbering_plan,
            self.nature_of_address,
            self.digits
        )
    }
}

/// A SUA Source / Destination Address (RFC 3868 §3.10.2 / §3.10.3).
///
/// Carries the Routing Indicator plus any of the Global Title, Point Code and
/// Subsystem Number sub-parameters. The Address Indicator "include" bits (which
/// tell an interworking SG which fields to populate in the SCCP called/calling
/// party address) are stored separately from sub-parameter presence, because
/// RFC 3868 §3.10.2.2 allows a field to be present in the SUA message yet marked
/// "do not populate" (e.g. a PC used only for the MTP routing label). Any
/// sub-parameter this codec does not model (Hostname, IPv4, IPv6) is preserved
/// verbatim in [`other`](Self::other) for lossless round-trips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuaAddress {
    /// How this address is routed.
    pub routing_indicator: RoutingIndicator,
    /// Address Indicator bit 3, include the Global Title in the SCCP address.
    pub include_gt: bool,
    /// Address Indicator bit 2, include the Point Code in the SCCP address.
    pub include_pc: bool,
    /// Address Indicator bit 1, include the SSN in the SCCP address.
    pub include_ssn: bool,
    /// Optional Global Title.
    pub global_title: Option<GlobalTitle>,
    /// Optional Point Code (32-bit).
    pub point_code: Option<u32>,
    /// Optional Subsystem Number.
    pub ssn: Option<u8>,
    /// Any other sub-parameters (Hostname / IP address), kept raw.
    pub other: Vec<Parameter>,
}

impl SuaAddress {
    /// Create a GT-routed address (routing indicator = Route on Global Title),
    /// optionally with an SSN. The Address Indicator include-bits are set to
    /// match which fields are present.
    pub fn with_gt(gt: GlobalTitle, ssn: Option<u8>) -> Self {
        Self {
            routing_indicator: RoutingIndicator::RouteOnGlobalTitle,
            include_gt: true,
            include_pc: false,
            include_ssn: ssn.is_some(),
            global_title: Some(gt),
            point_code: None,
            ssn,
            other: Vec::new(),
        }
    }

    /// Create an SSN+PC-routed address (routing indicator = Route on SSN + PC).
    /// The Address Indicator include-bits are set to match which fields are
    /// present.
    pub fn with_ssn_pc(ssn: u8, point_code: u32) -> Self {
        Self {
            routing_indicator: RoutingIndicator::RouteOnSsnAndPc,
            include_gt: false,
            include_pc: true,
            include_ssn: true,
            global_title: None,
            point_code: Some(point_code),
            ssn: Some(ssn),
            other: Vec::new(),
        }
    }

    /// The 16-bit Address Indicator: bit 1 SSN (0x0001), bit 2 PC (0x0002),
    /// bit 3 GT (0x0004).
    pub fn address_indicator(&self) -> u16 {
        (if self.include_ssn { 0x0001 } else { 0 })
            | (if self.include_pc { 0x0002 } else { 0 })
            | (if self.include_gt { 0x0004 } else { 0 })
    }

    /// Decode a SUA address from a Source/Destination Address parameter value.
    pub fn decode(value: &[u8]) -> Result<Self, SuaError> {
        if value.len() < 4 {
            return Err(SuaError::TooShort {
                expected: 4,
                actual: value.len(),
            });
        }
        let ri = u16::from_be_bytes([value[0], value[1]]);
        let ai = u16::from_be_bytes([value[2], value[3]]);
        let routing_indicator = RoutingIndicator::from_u16(ri)?;

        let mut global_title = None;
        let mut point_code = None;
        let mut ssn = None;
        let mut other = Vec::new();

        for sub in parameter::decode_parameters(&value[4..])? {
            match sub.tag {
                tags::GLOBAL_TITLE => global_title = Some(GlobalTitle::decode(&sub.value)?),
                tags::POINT_CODE => {
                    if sub.value.len() < 4 {
                        return Err(SuaError::ParameterTooShort {
                            tag: tags::POINT_CODE,
                            expected: 4,
                            actual: sub.value.len(),
                        });
                    }
                    point_code = Some(u32::from_be_bytes([
                        sub.value[0],
                        sub.value[1],
                        sub.value[2],
                        sub.value[3],
                    ]));
                }
                tags::SUBSYSTEM_NUMBER => {
                    if sub.value.len() < 4 {
                        return Err(SuaError::ParameterTooShort {
                            tag: tags::SUBSYSTEM_NUMBER,
                            expected: 4,
                            actual: sub.value.len(),
                        });
                    }
                    // 3 reserved octets, then the SSN value.
                    ssn = Some(sub.value[3]);
                }
                _ => other.push(sub),
            }
        }

        Ok(Self {
            routing_indicator,
            include_gt: ai & 0x0004 != 0,
            include_pc: ai & 0x0002 != 0,
            include_ssn: ai & 0x0001 != 0,
            global_title,
            point_code,
            ssn,
            other,
        })
    }

    /// Encode the address to a Source/Destination Address parameter value
    /// (Routing Indicator + Address Indicator + sub-parameters).
    pub fn encode(&self) -> Result<Vec<u8>, SuaError> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.routing_indicator.value().to_be_bytes());
        v.extend_from_slice(&self.address_indicator().to_be_bytes());

        if let Some(gt) = &self.global_title {
            v.extend_from_slice(&Parameter::new(tags::GLOBAL_TITLE, gt.encode()?).encode());
        }
        if let Some(pc) = self.point_code {
            v.extend_from_slice(
                &Parameter::new(tags::POINT_CODE, pc.to_be_bytes().to_vec()).encode(),
            );
        }
        if let Some(ssn) = self.ssn {
            v.extend_from_slice(
                &Parameter::new(tags::SUBSYSTEM_NUMBER, vec![0, 0, 0, ssn]).encode(),
            );
        }
        for sub in &self.other {
            v.extend_from_slice(&sub.encode());
        }
        Ok(v)
    }

    /// The Global Title digits, if a Global Title is present.
    pub fn gt_digits(&self) -> Option<&str> {
        self.global_title.as_ref().map(|gt| gt.digits.as_str())
    }
}

impl fmt::Display for SuaAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SuaAddress [ri={}", self.routing_indicator)?;
        if let Some(gt) = &self.global_title {
            write!(f, ", gt={gt}")?;
        }
        if let Some(pc) = self.point_code {
            write!(f, ", pc={pc}")?;
        }
        if let Some(ssn) = self.ssn {
            write!(f, ", ssn={ssn}")?;
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gt_address_round_trip() {
        let gt = GlobalTitle::e164("15550142");
        let addr = SuaAddress::with_gt(gt, Some(8));
        let encoded = addr.encode().unwrap();
        let decoded = SuaAddress::decode(&encoded).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(decoded.gt_digits(), Some("15550142"));
        assert_eq!(decoded.ssn, Some(8));
        assert_eq!(
            decoded.routing_indicator,
            RoutingIndicator::RouteOnGlobalTitle
        );
    }

    #[test]
    fn ssn_pc_address_round_trip() {
        let addr = SuaAddress::with_ssn_pc(6, 0x0000_07D0); // SSN 6, PC 2000
        let decoded = SuaAddress::decode(&addr.encode().unwrap()).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(decoded.point_code, Some(2000));
        assert_eq!(decoded.ssn, Some(6));
        assert_eq!(decoded.routing_indicator, RoutingIndicator::RouteOnSsnAndPc);
    }

    #[test]
    fn address_indicator_bits() {
        let addr = SuaAddress::with_gt(GlobalTitle::e164("5550100"), Some(8));
        // GT (0x4) + SSN (0x1) present, PC absent.
        assert_eq!(addr.address_indicator(), 0x0005);

        let addr2 = SuaAddress::with_ssn_pc(8, 100);
        // PC (0x2) + SSN (0x1).
        assert_eq!(addr2.address_indicator(), 0x0003);
    }

    #[test]
    fn odd_length_gt_digits_round_trip() {
        let gt = GlobalTitle::e164("155501421"); // 9 digits (odd)
        let addr = SuaAddress::with_gt(gt, None);
        let decoded = SuaAddress::decode(&addr.encode().unwrap()).unwrap();
        assert_eq!(decoded.gt_digits(), Some("155501421"));
    }

    #[test]
    fn unknown_sub_parameter_is_preserved() {
        let mut addr = SuaAddress::with_ssn_pc(8, 100);
        // A Hostname sub-parameter (0x8005) this codec keeps opaque.
        addr.other
            .push(Parameter::new(tags::HOSTNAME, b"sg.example\0".to_vec()));
        let decoded = SuaAddress::decode(&addr.encode().unwrap()).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(decoded.other.len(), 1);
        assert_eq!(decoded.other[0].tag, tags::HOSTNAME);
    }

    #[test]
    fn include_bits_survive_when_pc_present_but_not_populated() {
        // RFC 3868 §3.10.2.2: a PC can be present in the message yet marked
        // "do not populate" (include bit 0). The codec preserves that.
        let mut addr = SuaAddress::with_gt(GlobalTitle::e164("5550100"), Some(8));
        addr.point_code = Some(2000);
        addr.include_pc = false; // present, but not populated into the SCCP address
        let decoded = SuaAddress::decode(&addr.encode().unwrap()).unwrap();
        assert_eq!(decoded.point_code, Some(2000));
        assert!(!decoded.include_pc);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn decode_rejects_bad_routing_indicator() {
        // RI = 7 is undefined.
        let bytes = [0x00, 0x07, 0x00, 0x05];
        assert!(matches!(
            SuaAddress::decode(&bytes),
            Err(SuaError::InvalidRoutingIndicator(7))
        ));
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(matches!(
            SuaAddress::decode(&[0x00, 0x01]),
            Err(SuaError::TooShort { .. })
        ));
    }

    #[test]
    fn global_title_e164_defaults() {
        let gt = GlobalTitle::e164("5550142");
        assert_eq!(gt.gti, 4);
        assert_eq!(gt.numbering_plan, 1);
        assert_eq!(gt.nature_of_address, 4);
    }

    #[test]
    fn display_contains_digits() {
        let addr = SuaAddress::with_gt(GlobalTitle::e164("15550142"), Some(8));
        let s = format!("{addr}");
        assert!(s.contains("15550142"));
        assert!(s.contains("GT(1)"));
    }
}
