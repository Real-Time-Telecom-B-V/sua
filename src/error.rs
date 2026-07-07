//! Error type for SUA encoding and decoding.

/// Errors that can occur during SUA message processing.
#[derive(Debug, thiserror::Error)]
pub enum SuaError {
    /// The input was shorter than the minimum required to decode this item.
    #[error("message too short: expected at least {expected} bytes, got {actual}")]
    TooShort {
        /// Minimum number of bytes required.
        expected: usize,
        /// Number of bytes actually available.
        actual: usize,
    },

    /// The header carried a version other than the supported SUA version (1).
    #[error("invalid version: expected 1, got {0}")]
    InvalidVersion(u8),

    /// The header carried a message class not defined by RFC 3868.
    #[error("invalid message class: {0}")]
    InvalidMessageClass(u8),

    /// The `(class, type)` pair does not correspond to a known message type.
    #[error("invalid message type: class={class}, type={msg_type}")]
    InvalidMessageType {
        /// The message class octet from the header.
        class: u8,
        /// The message type octet from the header.
        msg_type: u8,
    },

    /// A parameter's declared length was invalid (e.g. smaller than the 4-byte
    /// tag+length header).
    #[error("invalid parameter: tag=0x{tag:04x}, length={length}")]
    InvalidParameter {
        /// The parameter tag.
        tag: u16,
        /// The declared parameter length (including the 4-byte header).
        length: u16,
    },

    /// A parameter's declared length ran past the end of the available bytes.
    #[error(
        "parameter too short: tag=0x{tag:04x}, expected at least {expected} bytes, got {actual}"
    )]
    ParameterTooShort {
        /// The parameter tag.
        tag: u16,
        /// Minimum number of bytes required for the declared length.
        expected: usize,
        /// Number of bytes actually available.
        actual: usize,
    },

    /// A required parameter (identified by its tag) was absent from the message.
    #[error("missing required parameter: tag=0x{0:04x}")]
    MissingParameter(u16),

    /// The Routing Indicator field of an address carried an undefined value
    /// (RFC 3868 §3.10.2.1 defines only 0-4).
    #[error("invalid routing indicator: {0}")]
    InvalidRoutingIndicator(u16),

    /// A Global Title digit could not be encoded to BCD (not `0`-`9`, `*`, `#`,
    /// or `a`-`c`).
    #[error("invalid BCD digit: 0x{0:02x}")]
    InvalidBcdDigit(u8),
}
