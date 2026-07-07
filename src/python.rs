//! PyO3 bindings, `pip install sua` gives a Rust-backed wheel exposing the
//! **same** SUA (RFC 3868) codec the crate ships.
//!
//! Compiled only with `--features python`; the default crate build is pyo3-free, so
//! `cargo add sua` / crates.io consumers pull zero pyo3. Two entry points share one
//! `add_contents()`:
//! * `#[pymodule] fn _sua`, the standalone wheel (maturin `module-name`).
//! * `pub fn register(py, parent)`, mount `sua` as a submodule of another
//!   extension, so a host can expose sua without a second shared object.
//!
//! The Python surface is a faithful mirror of the codec: [`SuaMessage`] carries
//! typed constructors for the common messages (`cldt`, `cldr`, `asp_up`, `duna`,
//! …), `encode()` produces the wire form, and `sua.decode(...)` parses it back.
//! [`SuaAddress`] and [`GlobalTitle`] model the GT / SSN / PC addressing.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::{
    tags, GlobalTitle as CoreGlobalTitle, MessageType as CoreMessageType,
    RoutingIndicator as CoreRoutingIndicator, SuaAddress as CoreSuaAddress,
    SuaError as CoreSuaError, SuaMessage, DEFAULT_HOP_COUNTER, SCTP_PPID, VERSION,
};

// ── Error mapping ───────────────────────────────────────────────────────────
create_exception!(
    sua,
    SuaError,
    PyException,
    "SUA protocol / codec error (RFC 3868)."
);

fn sua_err(e: CoreSuaError) -> PyErr {
    SuaError::new_err(e.to_string())
}

// ── MessageType (RFC 3868 §3.1.3) ───────────────────────────────────────────
/// SUA message types across the classes (MGMT / SNM / ASPSM / ASPTM / CL / CO /
/// RKM). Carried on [`SuaMessage.message_type`](SuaMessage).
#[pyclass(name = "MessageType", module = "sua._sua", eq, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PyMessageType {
    Error,
    Notify,
    Duna,
    Dava,
    Daud,
    Scon,
    Dupu,
    Drst,
    AspUp,
    AspDown,
    Heartbeat,
    AspUpAck,
    AspDownAck,
    HeartbeatAck,
    AspActive,
    AspInactive,
    AspActiveAck,
    AspInactiveAck,
    Cldt,
    Cldr,
    Core,
    Coak,
    Coref,
    Relre,
    Relco,
    Resco,
    Resre,
    Codt,
    Coda,
    Coerr,
    Coit,
    RegReq,
    RegRsp,
    DeregReq,
    DeregRsp,
}

impl PyMessageType {
    fn from_core(t: CoreMessageType) -> Self {
        match t {
            CoreMessageType::Error => Self::Error,
            CoreMessageType::Notify => Self::Notify,
            CoreMessageType::Duna => Self::Duna,
            CoreMessageType::Dava => Self::Dava,
            CoreMessageType::Daud => Self::Daud,
            CoreMessageType::Scon => Self::Scon,
            CoreMessageType::Dupu => Self::Dupu,
            CoreMessageType::Drst => Self::Drst,
            CoreMessageType::AspUp => Self::AspUp,
            CoreMessageType::AspDown => Self::AspDown,
            CoreMessageType::Heartbeat => Self::Heartbeat,
            CoreMessageType::AspUpAck => Self::AspUpAck,
            CoreMessageType::AspDownAck => Self::AspDownAck,
            CoreMessageType::HeartbeatAck => Self::HeartbeatAck,
            CoreMessageType::AspActive => Self::AspActive,
            CoreMessageType::AspInactive => Self::AspInactive,
            CoreMessageType::AspActiveAck => Self::AspActiveAck,
            CoreMessageType::AspInactiveAck => Self::AspInactiveAck,
            CoreMessageType::Cldt => Self::Cldt,
            CoreMessageType::Cldr => Self::Cldr,
            CoreMessageType::Core => Self::Core,
            CoreMessageType::Coak => Self::Coak,
            CoreMessageType::Coref => Self::Coref,
            CoreMessageType::Relre => Self::Relre,
            CoreMessageType::Relco => Self::Relco,
            CoreMessageType::Resco => Self::Resco,
            CoreMessageType::Resre => Self::Resre,
            CoreMessageType::Codt => Self::Codt,
            CoreMessageType::Coda => Self::Coda,
            CoreMessageType::Coerr => Self::Coerr,
            CoreMessageType::Coit => Self::Coit,
            CoreMessageType::RegReq => Self::RegReq,
            CoreMessageType::RegRsp => Self::RegRsp,
            CoreMessageType::DeregReq => Self::DeregReq,
            CoreMessageType::DeregRsp => Self::DeregRsp,
        }
    }

    fn to_core(self) -> CoreMessageType {
        match self {
            Self::Error => CoreMessageType::Error,
            Self::Notify => CoreMessageType::Notify,
            Self::Duna => CoreMessageType::Duna,
            Self::Dava => CoreMessageType::Dava,
            Self::Daud => CoreMessageType::Daud,
            Self::Scon => CoreMessageType::Scon,
            Self::Dupu => CoreMessageType::Dupu,
            Self::Drst => CoreMessageType::Drst,
            Self::AspUp => CoreMessageType::AspUp,
            Self::AspDown => CoreMessageType::AspDown,
            Self::Heartbeat => CoreMessageType::Heartbeat,
            Self::AspUpAck => CoreMessageType::AspUpAck,
            Self::AspDownAck => CoreMessageType::AspDownAck,
            Self::HeartbeatAck => CoreMessageType::HeartbeatAck,
            Self::AspActive => CoreMessageType::AspActive,
            Self::AspInactive => CoreMessageType::AspInactive,
            Self::AspActiveAck => CoreMessageType::AspActiveAck,
            Self::AspInactiveAck => CoreMessageType::AspInactiveAck,
            Self::Cldt => CoreMessageType::Cldt,
            Self::Cldr => CoreMessageType::Cldr,
            Self::Core => CoreMessageType::Core,
            Self::Coak => CoreMessageType::Coak,
            Self::Coref => CoreMessageType::Coref,
            Self::Relre => CoreMessageType::Relre,
            Self::Relco => CoreMessageType::Relco,
            Self::Resco => CoreMessageType::Resco,
            Self::Resre => CoreMessageType::Resre,
            Self::Codt => CoreMessageType::Codt,
            Self::Coda => CoreMessageType::Coda,
            Self::Coerr => CoreMessageType::Coerr,
            Self::Coit => CoreMessageType::Coit,
            Self::RegReq => CoreMessageType::RegReq,
            Self::RegRsp => CoreMessageType::RegRsp,
            Self::DeregReq => CoreMessageType::DeregReq,
            Self::DeregRsp => CoreMessageType::DeregRsp,
        }
    }
}

#[pymethods]
impl PyMessageType {
    /// The `(class, type)` header octet pair for this message type.
    fn class_and_type(&self) -> (u8, u8) {
        self.to_core().class_and_type()
    }

    fn __repr__(&self) -> String {
        format!("MessageType.{}", self.to_core())
    }
}

// ── RoutingIndicator (RFC 3868 §3.10.2.1) ───────────────────────────────────
/// How a SUA address is routed. Carried on [`SuaAddress.routing_indicator`](SuaAddress).
#[pyclass(name = "RoutingIndicator", module = "sua._sua", eq, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PyRoutingIndicator {
    Reserved,
    RouteOnGlobalTitle,
    RouteOnSsnAndPc,
    RouteOnHostname,
    RouteOnSsnAndIp,
}

impl PyRoutingIndicator {
    fn from_core(ri: CoreRoutingIndicator) -> Self {
        match ri {
            CoreRoutingIndicator::Reserved => Self::Reserved,
            CoreRoutingIndicator::RouteOnGlobalTitle => Self::RouteOnGlobalTitle,
            CoreRoutingIndicator::RouteOnSsnAndPc => Self::RouteOnSsnAndPc,
            CoreRoutingIndicator::RouteOnHostname => Self::RouteOnHostname,
            CoreRoutingIndicator::RouteOnSsnAndIp => Self::RouteOnSsnAndIp,
        }
    }
}

#[pymethods]
impl PyRoutingIndicator {
    /// The raw 16-bit routing-indicator value.
    fn value(&self) -> u16 {
        match self {
            Self::Reserved => 0,
            Self::RouteOnGlobalTitle => 1,
            Self::RouteOnSsnAndPc => 2,
            Self::RouteOnHostname => 3,
            Self::RouteOnSsnAndIp => 4,
        }
    }

    fn __repr__(&self) -> String {
        let name = match self {
            Self::Reserved => "Reserved",
            Self::RouteOnGlobalTitle => "RouteOnGlobalTitle",
            Self::RouteOnSsnAndPc => "RouteOnSsnAndPc",
            Self::RouteOnHostname => "RouteOnHostname",
            Self::RouteOnSsnAndIp => "RouteOnSsnAndIp",
        };
        format!("RoutingIndicator.{name}")
    }
}

// ── GlobalTitle (RFC 3868 §3.10.2.3) ────────────────────────────────────────
/// A SUA Global Title: indicator + translation type / numbering plan / nature of
/// address + BCD digits.
#[pyclass(name = "GlobalTitle", module = "sua._sua", from_py_object)]
#[derive(Clone)]
pub struct PyGlobalTitle {
    /// Global Title Indicator (0-4).
    #[pyo3(get)]
    pub gti: u8,
    /// Translation type.
    #[pyo3(get)]
    pub translation_type: u8,
    /// Numbering plan (1 = ISDN/E.164).
    #[pyo3(get)]
    pub numbering_plan: u8,
    /// Nature of address (4 = international number).
    #[pyo3(get)]
    pub nature_of_address: u8,
    /// The address digits.
    #[pyo3(get)]
    pub digits: String,
}

impl PyGlobalTitle {
    fn to_core(&self) -> CoreGlobalTitle {
        CoreGlobalTitle::new(
            self.gti,
            self.translation_type,
            self.numbering_plan,
            self.nature_of_address,
            self.digits.clone(),
        )
    }

    fn from_core(gt: CoreGlobalTitle) -> Self {
        Self {
            gti: gt.gti,
            translation_type: gt.translation_type,
            numbering_plan: gt.numbering_plan,
            nature_of_address: gt.nature_of_address,
            digits: gt.digits,
        }
    }
}

#[pymethods]
impl PyGlobalTitle {
    #[new]
    #[pyo3(signature = (gti, translation_type, numbering_plan, nature_of_address, digits))]
    fn new(
        gti: u8,
        translation_type: u8,
        numbering_plan: u8,
        nature_of_address: u8,
        digits: String,
    ) -> Self {
        Self {
            gti,
            translation_type,
            numbering_plan,
            nature_of_address,
            digits,
        }
    }

    /// A GTI=4 international E.164 Global Title (translation type 0, numbering
    /// plan 1, nature of address 4).
    #[staticmethod]
    fn e164(digits: String) -> Self {
        Self::from_core(CoreGlobalTitle::e164(digits))
    }

    fn __repr__(&self) -> String {
        format!(
            "GlobalTitle(gti={}, tt={}, np={}, noa={}, digits={:?})",
            self.gti,
            self.translation_type,
            self.numbering_plan,
            self.nature_of_address,
            self.digits
        )
    }
}

// ── SuaAddress (RFC 3868 §3.10.2) ───────────────────────────────────────────
/// A SUA Source / Destination Address (GT / PC / SSN with a Routing Indicator).
#[pyclass(name = "SuaAddress", module = "sua._sua", from_py_object)]
#[derive(Clone)]
pub struct PySuaAddress {
    inner: CoreSuaAddress,
}

impl PySuaAddress {
    fn wrap(inner: CoreSuaAddress) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PySuaAddress {
    /// A GT-routed address (routing indicator = Route on Global Title), with an
    /// optional SSN.
    #[staticmethod]
    #[pyo3(signature = (global_title, ssn = None))]
    fn with_gt(global_title: PyGlobalTitle, ssn: Option<u8>) -> Self {
        Self::wrap(CoreSuaAddress::with_gt(global_title.to_core(), ssn))
    }

    /// An SSN+PC-routed address (routing indicator = Route on SSN + PC).
    #[staticmethod]
    fn with_ssn_pc(ssn: u8, point_code: u32) -> Self {
        Self::wrap(CoreSuaAddress::with_ssn_pc(ssn, point_code))
    }

    /// How this address is routed.
    #[getter]
    fn routing_indicator(&self) -> PyRoutingIndicator {
        PyRoutingIndicator::from_core(self.inner.routing_indicator)
    }

    /// The Global Title, if present.
    #[getter]
    fn global_title(&self) -> Option<PyGlobalTitle> {
        self.inner
            .global_title
            .clone()
            .map(PyGlobalTitle::from_core)
    }

    /// The Point Code, if present.
    #[getter]
    fn point_code(&self) -> Option<u32> {
        self.inner.point_code
    }

    /// The Subsystem Number, if present.
    #[getter]
    fn ssn(&self) -> Option<u8> {
        self.inner.ssn
    }

    /// Address Indicator bit 3, include the Global Title in the SCCP address.
    #[getter]
    fn include_gt(&self) -> bool {
        self.inner.include_gt
    }

    /// Address Indicator bit 2, include the Point Code in the SCCP address.
    #[getter]
    fn include_pc(&self) -> bool {
        self.inner.include_pc
    }

    /// Address Indicator bit 1, include the SSN in the SCCP address.
    #[getter]
    fn include_ssn(&self) -> bool {
        self.inner.include_ssn
    }

    /// The Global Title digits, if a Global Title is present.
    fn gt_digits(&self) -> Option<String> {
        self.inner.gt_digits().map(|s| s.to_string())
    }

    /// The 16-bit Address Indicator value.
    fn address_indicator(&self) -> u16 {
        self.inner.address_indicator()
    }

    /// Encode the address to its parameter value bytes.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.encode().map_err(sua_err)?;
        Ok(PyBytes::new(py, &bytes))
    }

    fn __repr__(&self) -> String {
        format!("SuaAddress({})", self.inner)
    }
}

// ── SuaMessage ──────────────────────────────────────────────────────────────
/// A complete SUA message. Build one with a typed constructor
/// (`SuaMessage.cldt(...)`, `.asp_up(...)`, `.duna(...)`, …), call `encode()` for
/// the wire form, and `sua.decode(...)` to parse bytes back.
#[pyclass(name = "SuaMessage", module = "sua._sua", skip_from_py_object)]
#[derive(Clone)]
pub struct PySuaMessage {
    inner: SuaMessage,
}

impl PySuaMessage {
    fn wrap(inner: SuaMessage) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PySuaMessage {
    /// The message type (which implies the message class).
    #[getter]
    fn message_type(&self) -> PyMessageType {
        PyMessageType::from_core(self.inner.message_type)
    }

    /// Create a CLDT (Connectionless Data Transfer) carrying an SCCP-user payload.
    #[staticmethod]
    #[pyo3(signature = (source, destination, *, routing_context, protocol_class = 0, sequence_control = 0, ss7_hop_count = None, data = Vec::new()))]
    fn cldt(
        source: PySuaAddress,
        destination: PySuaAddress,
        routing_context: u32,
        protocol_class: u8,
        sequence_control: u32,
        ss7_hop_count: Option<u8>,
        data: Vec<u8>,
    ) -> PyResult<Self> {
        SuaMessage::cldt(
            routing_context,
            protocol_class,
            &source.inner,
            &destination.inner,
            sequence_control,
            ss7_hop_count,
            data,
        )
        .map(Self::wrap)
        .map_err(sua_err)
    }

    /// Create a CLDR (Connectionless Data Response) carrying an SCCP cause.
    #[staticmethod]
    #[pyo3(signature = (source, destination, *, routing_context, cause_type, cause_value, data = None))]
    fn cldr(
        source: PySuaAddress,
        destination: PySuaAddress,
        routing_context: u32,
        cause_type: u8,
        cause_value: u8,
        data: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        SuaMessage::cldr(
            routing_context,
            cause_type,
            cause_value,
            &source.inner,
            &destination.inner,
            data,
        )
        .map(Self::wrap)
        .map_err(sua_err)
    }

    /// Create an ASP-UP message (optionally with ASP Identifier and Info String).
    #[staticmethod]
    #[pyo3(signature = (asp_id = None, info = None))]
    fn asp_up(asp_id: Option<u32>, info: Option<&str>) -> Self {
        Self::wrap(SuaMessage::asp_up(asp_id, info))
    }

    /// Create an ASP-UP-ACK message.
    #[staticmethod]
    #[pyo3(signature = (info = None))]
    fn asp_up_ack(info: Option<&str>) -> Self {
        Self::wrap(SuaMessage::asp_up_ack(info))
    }

    /// Create an ASP-DOWN message.
    #[staticmethod]
    #[pyo3(signature = (info = None))]
    fn asp_down(info: Option<&str>) -> Self {
        Self::wrap(SuaMessage::asp_down(info))
    }

    /// Create an ASP-DOWN-ACK message.
    #[staticmethod]
    #[pyo3(signature = (info = None))]
    fn asp_down_ack(info: Option<&str>) -> Self {
        Self::wrap(SuaMessage::asp_down_ack(info))
    }

    /// Create an ASP-ACTIVE message (optional traffic mode + routing context).
    #[staticmethod]
    #[pyo3(signature = (traffic_mode = None, routing_context = None))]
    fn asp_active(traffic_mode: Option<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(SuaMessage::asp_active(traffic_mode, routing_context))
    }

    /// Create an ASP-ACTIVE-ACK message.
    #[staticmethod]
    #[pyo3(signature = (traffic_mode = None, routing_context = None))]
    fn asp_active_ack(traffic_mode: Option<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(SuaMessage::asp_active_ack(traffic_mode, routing_context))
    }

    /// Create an ASP-INACTIVE message.
    #[staticmethod]
    #[pyo3(signature = (routing_context = None))]
    fn asp_inactive(routing_context: Option<u32>) -> Self {
        Self::wrap(SuaMessage::asp_inactive(routing_context))
    }

    /// Create an ASP-INACTIVE-ACK message.
    #[staticmethod]
    #[pyo3(signature = (routing_context = None))]
    fn asp_inactive_ack(routing_context: Option<u32>) -> Self {
        Self::wrap(SuaMessage::asp_inactive_ack(routing_context))
    }

    /// Create a BEAT (heartbeat) message.
    #[staticmethod]
    #[pyo3(signature = (data = None))]
    fn heartbeat(data: Option<Vec<u8>>) -> Self {
        Self::wrap(SuaMessage::heartbeat(data))
    }

    /// Create a BEAT-ACK (heartbeat ack) message.
    #[staticmethod]
    #[pyo3(signature = (data = None))]
    fn heartbeat_ack(data: Option<Vec<u8>>) -> Self {
        Self::wrap(SuaMessage::heartbeat_ack(data))
    }

    /// Create a DUNA (Destination Unavailable) message.
    #[staticmethod]
    #[pyo3(signature = (affected_pcs, *, routing_context = None))]
    fn duna(affected_pcs: Vec<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(SuaMessage::duna(routing_context, &affected_pcs))
    }

    /// Create a DAVA (Destination Available) message.
    #[staticmethod]
    #[pyo3(signature = (affected_pcs, *, routing_context = None))]
    fn dava(affected_pcs: Vec<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(SuaMessage::dava(routing_context, &affected_pcs))
    }

    /// Create a DAUD (Destination State Audit) message.
    #[staticmethod]
    #[pyo3(signature = (affected_pcs, *, routing_context = None))]
    fn daud(affected_pcs: Vec<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(SuaMessage::daud(routing_context, &affected_pcs))
    }

    /// Create an ERR message.
    #[staticmethod]
    #[pyo3(signature = (error_code, *, routing_context = None, diagnostic_info = None))]
    fn error(
        error_code: u32,
        routing_context: Option<u32>,
        diagnostic_info: Option<Vec<u8>>,
    ) -> Self {
        Self::wrap(SuaMessage::error(
            error_code,
            routing_context,
            diagnostic_info,
        ))
    }

    /// Create a NTFY (Notify) message.
    #[staticmethod]
    #[pyo3(signature = (status, *, asp_id = None, routing_context = None))]
    fn notify(status: u32, asp_id: Option<u32>, routing_context: Option<u32>) -> Self {
        Self::wrap(SuaMessage::notify(status, asp_id, routing_context))
    }

    /// The Routing Context value, if present.
    fn routing_context(&self) -> Option<u32> {
        self.inner.routing_context()
    }

    /// The Protocol Class octet, if present.
    fn protocol_class(&self) -> Option<u8> {
        self.inner.protocol_class()
    }

    /// The Sequence Control value, if present.
    fn sequence_control(&self) -> Option<u32> {
        self.inner.sequence_control()
    }

    /// The SS7 Hop Counter, if present.
    fn ss7_hop_count(&self) -> Option<u8> {
        self.inner.ss7_hop_count()
    }

    /// The Source Address (calling party). Raises `SuaError` if absent.
    fn source_address(&self) -> PyResult<PySuaAddress> {
        self.inner
            .source_address()
            .map(PySuaAddress::wrap)
            .map_err(sua_err)
    }

    /// The Destination Address (called party). Raises `SuaError` if absent.
    fn destination_address(&self) -> PyResult<PySuaAddress> {
        self.inner
            .destination_address()
            .map(PySuaAddress::wrap)
            .map_err(sua_err)
    }

    /// The Data (SCCP-user / TCAP) payload as `bytes`, if present.
    fn data<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.data().map(|d| PyBytes::new(py, d))
    }

    /// The SCCP Cause as `(cause_type, cause_value)`, if present.
    fn sccp_cause(&self) -> Option<(u8, u8)> {
        self.inner.sccp_cause()
    }

    /// The affected point codes carried in an SNM message (DUNA/DAVA/DAUD/…).
    fn affected_point_codes(&self) -> Vec<u32> {
        self.inner.affected_point_codes()
    }

    /// The parameter tags present on this message, in wire order.
    fn parameter_tags(&self) -> Vec<u16> {
        self.inner.parameters.iter().map(|p| p.tag).collect()
    }

    /// Encode the complete SUA message (common header + TLV parameters).
    fn encode<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.encode())
    }

    fn __repr__(&self) -> String {
        format!(
            "SuaMessage(type={}, parameters={})",
            self.inner.message_type,
            self.inner.parameters.len()
        )
    }
}

// ── Point-code helpers ──────────────────────────────────────────────────────
/// Pack point codes into the on-wire Affected Point Code value (mask + 24-bit PC
/// each), the layout used by SNM messages.
#[pyfunction]
fn pack_affected_point_codes<'py>(py: Python<'py>, pcs: Vec<u32>) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &crate::pack_affected_point_codes(&pcs))
}

/// Unpack an Affected Point Code value back into point codes.
#[pyfunction]
fn unpack_affected_point_codes(data: &[u8]) -> Vec<u32> {
    crate::unpack_affected_point_codes(data)
}

// ── decode() ────────────────────────────────────────────────────────────────
/// Decode a complete SUA message, returning a [`SuaMessage`].
#[pyfunction]
fn decode(data: &[u8]) -> PyResult<PySuaMessage> {
    SuaMessage::decode(data)
        .map(PySuaMessage::wrap)
        .map_err(sua_err)
}

// ── Module wiring ───────────────────────────────────────────────────────────
fn add_tag(m: &Bound<'_, PyModule>, name: &str, tag: u16) -> PyResult<()> {
    m.add(name, tag)
}

fn add_contents(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SuaError", m.py().get_type::<SuaError>())?;
    m.add_class::<PyMessageType>()?;
    m.add_class::<PyRoutingIndicator>()?;
    m.add_class::<PyGlobalTitle>()?;
    m.add_class::<PySuaAddress>()?;
    m.add_class::<PySuaMessage>()?;
    m.add_function(wrap_pyfunction!(decode, m)?)?;
    m.add_function(wrap_pyfunction!(pack_affected_point_codes, m)?)?;
    m.add_function(wrap_pyfunction!(unpack_affected_point_codes, m)?)?;

    // Protocol constants (RFC 3868 §3.1 / §7).
    m.add("VERSION", VERSION)?;
    m.add("SCTP_PPID", SCTP_PPID)?;
    m.add("DEFAULT_HOP_COUNTER", DEFAULT_HOP_COUNTER)?;

    // Well-known parameter tags (RFC 3868 §3.9 / §3.10), prefixed `TAG_`.
    add_tag(m, "TAG_INFO_STRING", tags::INFO_STRING)?;
    add_tag(m, "TAG_ROUTING_CONTEXT", tags::ROUTING_CONTEXT)?;
    add_tag(m, "TAG_DIAGNOSTIC_INFO", tags::DIAGNOSTIC_INFO)?;
    add_tag(m, "TAG_HEARTBEAT_DATA", tags::HEARTBEAT_DATA)?;
    add_tag(m, "TAG_TRAFFIC_MODE_TYPE", tags::TRAFFIC_MODE_TYPE)?;
    add_tag(m, "TAG_ERROR_CODE", tags::ERROR_CODE)?;
    add_tag(m, "TAG_STATUS", tags::STATUS)?;
    add_tag(m, "TAG_ASP_IDENTIFIER", tags::ASP_IDENTIFIER)?;
    add_tag(m, "TAG_AFFECTED_POINT_CODE", tags::AFFECTED_POINT_CODE)?;
    add_tag(m, "TAG_CORRELATION_ID", tags::CORRELATION_ID)?;
    add_tag(m, "TAG_SS7_HOP_COUNTER", tags::SS7_HOP_COUNTER)?;
    add_tag(m, "TAG_SOURCE_ADDRESS", tags::SOURCE_ADDRESS)?;
    add_tag(m, "TAG_DESTINATION_ADDRESS", tags::DESTINATION_ADDRESS)?;
    add_tag(m, "TAG_SCCP_CAUSE", tags::SCCP_CAUSE)?;
    add_tag(m, "TAG_DATA", tags::DATA)?;
    add_tag(m, "TAG_NETWORK_APPEARANCE", tags::NETWORK_APPEARANCE)?;
    add_tag(m, "TAG_IMPORTANCE", tags::IMPORTANCE)?;
    add_tag(m, "TAG_MESSAGE_PRIORITY", tags::MESSAGE_PRIORITY)?;
    add_tag(m, "TAG_PROTOCOL_CLASS", tags::PROTOCOL_CLASS)?;
    add_tag(m, "TAG_SEQUENCE_CONTROL", tags::SEQUENCE_CONTROL)?;
    add_tag(m, "TAG_GLOBAL_TITLE", tags::GLOBAL_TITLE)?;
    add_tag(m, "TAG_POINT_CODE", tags::POINT_CODE)?;
    add_tag(m, "TAG_SUBSYSTEM_NUMBER", tags::SUBSYSTEM_NUMBER)?;

    Ok(())
}

/// Standalone wheel entry point (maturin `module-name = "sua._sua"`).
#[pymodule]
fn _sua(m: &Bound<'_, PyModule>) -> PyResult<()> {
    add_contents(m)
}

/// Embedding entry point: build a `sua` submodule and attach it to `parent`, so a
/// host extension can expose sua without a second shared object.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "sua")?;
    add_contents(&m)?;
    parent.setattr("sua", &m)?;
    Ok(())
}
