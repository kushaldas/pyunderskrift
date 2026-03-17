//! PyO3 wrappers for the underskrift inspect module.
//!
//! Exposes PDF object enumeration, signature metadata extraction, and
//! CMS extraction to Python.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyList, PyNone, PyString};

use crate::validate_pdf_input;

use underskrift::inspect::cms::extract_cms_by_object as rust_extract_cms_by_object;
use underskrift::inspect::signatures::{
    CoverageInfo as RustCoverageInfo, RevisionInfo as RustRevisionInfo,
};
use underskrift::inspect::{
    inspect_pdf as rust_inspect_pdf, inspect_signatures as rust_inspect_signatures,
    DssInfo as RustDssInfo, DssVriEntry as RustVriEntry, ObjectKind as RustObjectKind,
    PdfInspection as RustPdfInspection, PdfObjectInfo as RustPdfObjectInfo,
    PdfSignatureInspection as RustPdfSignatureInspection,
    SignatureFieldInfo as RustSignatureFieldInfo,
};

/// Maximum recursion depth for JSON-to-Python conversion.
const MAX_JSON_DEPTH: usize = 64;

/// Convert a serde_json::Value to a Python object.
fn json_value_to_py<'py>(
    py: Python<'py>,
    val: &serde_json::Value,
    depth: usize,
) -> PyResult<Bound<'py, PyAny>> {
    if depth > MAX_JSON_DEPTH {
        return Err(PyValueError::new_err(
            "JSON nesting depth exceeds maximum (64)",
        ));
    }
    match val {
        serde_json::Value::Null => Ok(PyNone::get(py).to_owned().into_any()),
        serde_json::Value::Bool(b) => Ok(PyBool::new(py, *b).to_owned().into_any()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                let obj: Bound<'py, PyAny> = i
                    .into_pyobject(py)
                    .map_err(|e| PyValueError::new_err(format!("int conversion failed: {e}")))?
                    .into_any();
                Ok(obj)
            } else if let Some(f) = n.as_f64() {
                Ok(PyFloat::new(py, f).into_any())
            } else {
                Ok(PyNone::get(py).to_owned().into_any())
            }
        }
        serde_json::Value::String(s) => Ok(PyString::new(py, s).into_any()),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_value_to_py(py, item, depth + 1)?)?;
            }
            Ok(list.into_any())
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, json_value_to_py(py, v, depth + 1)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

// ── ObjectKind ──────────────────────────────────────────────────────────────

/// The kind of a PDF object.
#[pyclass(eq, eq_int, skip_from_py_object)]
#[derive(Clone, PartialEq)]
pub enum ObjectKind {
    Dictionary = 0,
    Stream = 1,
    Array = 2,
    Name = 3,
    String = 4,
    Integer = 5,
    Real = 6,
    Boolean = 7,
    Null = 8,
    Reference = 9,
}

impl ObjectKind {
    fn from_rust(kind: &RustObjectKind) -> Self {
        match kind {
            RustObjectKind::Dictionary => ObjectKind::Dictionary,
            RustObjectKind::Stream => ObjectKind::Stream,
            RustObjectKind::Array => ObjectKind::Array,
            RustObjectKind::Name => ObjectKind::Name,
            RustObjectKind::String => ObjectKind::String,
            RustObjectKind::Integer => ObjectKind::Integer,
            RustObjectKind::Real => ObjectKind::Real,
            RustObjectKind::Boolean => ObjectKind::Boolean,
            RustObjectKind::Null => ObjectKind::Null,
            RustObjectKind::Reference => ObjectKind::Reference,
        }
    }
}

#[pymethods]
impl ObjectKind {
    fn __repr__(&self) -> String {
        let name = match self {
            ObjectKind::Dictionary => "Dictionary",
            ObjectKind::Stream => "Stream",
            ObjectKind::Array => "Array",
            ObjectKind::Name => "Name",
            ObjectKind::String => "String",
            ObjectKind::Integer => "Integer",
            ObjectKind::Real => "Real",
            ObjectKind::Boolean => "Boolean",
            ObjectKind::Null => "Null",
            ObjectKind::Reference => "Reference",
        };
        format!("ObjectKind.{name}")
    }

    /// Return the kind as a string label.
    fn as_str(&self) -> &'static str {
        match self {
            ObjectKind::Dictionary => "Dictionary",
            ObjectKind::Stream => "Stream",
            ObjectKind::Array => "Array",
            ObjectKind::Name => "Name",
            ObjectKind::String => "String",
            ObjectKind::Integer => "Integer",
            ObjectKind::Real => "Real",
            ObjectKind::Boolean => "Boolean",
            ObjectKind::Null => "Null",
            ObjectKind::Reference => "Reference",
        }
    }
}

// ── PdfObjectInfo ───────────────────────────────────────────────────────────

/// Information about a single PDF indirect object.
///
/// The ``data`` field contains the recursively serialized object data as
/// native Python types (dict/list/str/int/float/bool/None).
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct PdfObjectInfo {
    /// Object number.
    obj_num: u32,
    /// Generation number.
    gen_num: u16,
    /// The kind of object.
    kind: ObjectKind,
    /// The /Type entry value (e.g. "/Page"), if present.
    type_name: Option<String>,
    /// The /Subtype entry value, if present.
    subtype_name: Option<String>,
    /// Dictionary or stream dictionary keys.
    keys: Vec<String>,
    /// For streams, the /Length value.
    stream_length: Option<usize>,
    /// Serialized data stored as JSON for lazy conversion.
    data_json: serde_json::Value,
}

impl PdfObjectInfo {
    fn from_rust(r: &RustPdfObjectInfo) -> Self {
        Self {
            obj_num: r.obj_num,
            gen_num: r.gen_num,
            kind: ObjectKind::from_rust(&r.kind),
            type_name: r.type_name.clone(),
            subtype_name: r.subtype_name.clone(),
            keys: r.keys.clone(),
            stream_length: r.stream_length,
            data_json: r.data.clone(),
        }
    }
}

#[pymethods]
impl PdfObjectInfo {
    #[getter]
    fn obj_num(&self) -> u32 {
        self.obj_num
    }

    #[getter]
    fn gen_num(&self) -> u16 {
        self.gen_num
    }

    #[getter]
    fn kind(&self) -> ObjectKind {
        self.kind.clone()
    }

    #[getter]
    fn type_name(&self) -> Option<String> {
        self.type_name.clone()
    }

    #[getter]
    fn subtype_name(&self) -> Option<String> {
        self.subtype_name.clone()
    }

    #[getter]
    fn keys(&self) -> Vec<String> {
        self.keys.clone()
    }

    #[getter]
    fn stream_length(&self) -> Option<usize> {
        self.stream_length
    }

    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        json_value_to_py(py, &self.data_json, 0)
    }

    fn __repr__(&self) -> String {
        format!(
            "PdfObjectInfo(obj_num={}, kind={}, type={:?})",
            self.obj_num,
            self.kind.as_str(),
            self.type_name,
        )
    }
}

// ── PdfInspection ───────────────────────────────────────────────────────────

/// Result of inspecting a PDF's full object tree.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct PdfInspection {
    pdf_version: String,
    num_pages: usize,
    num_objects: usize,
    objects: Vec<PdfObjectInfo>,
    catalog_json: serde_json::Value,
}

impl PdfInspection {
    fn from_rust(r: &RustPdfInspection) -> Self {
        Self {
            pdf_version: r.pdf_version.clone(),
            num_pages: r.num_pages,
            num_objects: r.num_objects,
            objects: r.objects.iter().map(PdfObjectInfo::from_rust).collect(),
            catalog_json: r.catalog.clone(),
        }
    }
}

#[pymethods]
impl PdfInspection {
    #[getter]
    fn pdf_version(&self) -> String {
        self.pdf_version.clone()
    }

    #[getter]
    fn num_pages(&self) -> usize {
        self.num_pages
    }

    #[getter]
    fn num_objects(&self) -> usize {
        self.num_objects
    }

    #[getter]
    fn objects(&self) -> Vec<PdfObjectInfo> {
        self.objects.clone()
    }

    #[getter]
    fn catalog<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        json_value_to_py(py, &self.catalog_json, 0)
    }

    fn __repr__(&self) -> String {
        format!(
            "PdfInspection(version={:?}, pages={}, objects={})",
            self.pdf_version, self.num_pages, self.num_objects,
        )
    }
}

// ── CoverageInfo ────────────────────────────────────────────────────────────

/// ByteRange coverage information for a signature.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct CoverageInfo {
    /// Total signed bytes.
    pub signed_bytes: i64,
    /// Total file size.
    pub file_size: i64,
    /// Percentage of file signed.
    pub percentage: f64,
    /// Start of the unsigned gap (Contents).
    pub gap_start: i64,
    /// End of the unsigned gap.
    pub gap_end: i64,
    /// Size of the unsigned gap.
    pub gap_size: i64,
}

impl CoverageInfo {
    fn from_rust(r: &RustCoverageInfo) -> Self {
        Self {
            signed_bytes: r.signed_bytes,
            file_size: r.file_size,
            percentage: r.percentage,
            gap_start: r.gap_start,
            gap_end: r.gap_end,
            gap_size: r.gap_size,
        }
    }
}

#[pymethods]
impl CoverageInfo {
    fn __repr__(&self) -> String {
        format!(
            "CoverageInfo(signed={}, file_size={}, pct={:.1}%)",
            self.signed_bytes, self.file_size, self.percentage,
        )
    }
}

// ── SignatureFieldInfo ──────────────────────────────────────────────────────

/// Information about a single signature field.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct SignatureFieldInfo {
    /// Field name from /T.
    pub field_name: Option<String>,
    /// Object number of the signature value dictionary.
    pub obj_num: Option<u32>,
    /// /Filter value (e.g. "/Adobe.PPKLite").
    pub filter: Option<String>,
    /// /SubFilter value (e.g. "/adbe.pkcs7.detached", "/ETSI.CAdES.detached").
    pub sub_filter: Option<String>,
    /// /Name (signer name).
    pub name: Option<String>,
    /// /Reason.
    pub reason: Option<String>,
    /// /Location.
    pub location: Option<String>,
    /// /ContactInfo.
    pub contact_info: Option<String>,
    /// /M signing time string.
    pub signing_time: Option<String>,
    /// ByteRange array [offset1, length1, offset2, length2].
    pub byte_range: Option<[i64; 4]>,
    /// Coverage info.
    pub coverage: Option<CoverageInfo>,
    /// Length of the raw /Contents bytes.
    pub contents_length: Option<usize>,
    /// First 32 bytes of /Contents as hex string.
    pub contents_hex_preview: Option<String>,
    /// DocMDP permissions (1=no changes, 2=form fill, 3=annotations+form).
    pub doc_mdp_permissions: Option<i64>,
    /// Application name from /Prop_Build /App /Name.
    pub build_app_name: Option<String>,
}

impl SignatureFieldInfo {
    fn from_rust(r: &RustSignatureFieldInfo) -> Self {
        Self {
            field_name: r.field_name.clone(),
            obj_num: r.obj_num,
            filter: r.filter.clone(),
            sub_filter: r.sub_filter.clone(),
            name: r.name.clone(),
            reason: r.reason.clone(),
            location: r.location.clone(),
            contact_info: r.contact_info.clone(),
            signing_time: r.signing_time.clone(),
            byte_range: r.byte_range,
            coverage: r.coverage.as_ref().map(CoverageInfo::from_rust),
            contents_length: r.contents_length,
            contents_hex_preview: r.contents_hex_preview.clone(),
            doc_mdp_permissions: r.doc_mdp_permissions,
            build_app_name: r.build_app_name.clone(),
        }
    }
}

#[pymethods]
impl SignatureFieldInfo {
    fn __repr__(&self) -> String {
        format!(
            "SignatureFieldInfo(field={:?}, filter={:?}, sub_filter={:?})",
            self.field_name, self.filter, self.sub_filter,
        )
    }
}

// ── VriEntry ────────────────────────────────────────────────────────────────

/// A VRI (Validation Related Information) entry from the DSS.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct VriEntry {
    /// The hash key (uppercase hex SHA-1 of signature /Contents).
    pub hash_key: String,
    /// Number of certificates.
    pub num_certs: usize,
    /// Number of OCSP responses.
    pub num_ocsps: usize,
    /// Number of CRLs.
    pub num_crls: usize,
    /// DER-encoded certificates.
    pub certs: Vec<Vec<u8>>,
    /// DER-encoded OCSP responses.
    pub ocsps: Vec<Vec<u8>>,
    /// DER-encoded CRLs.
    pub crls: Vec<Vec<u8>>,
}

impl VriEntry {
    fn from_rust(r: &RustVriEntry) -> Self {
        Self {
            hash_key: r.hash_key.clone(),
            num_certs: r.num_certs,
            num_ocsps: r.num_ocsps,
            num_crls: r.num_crls,
            certs: r.certs.clone(),
            ocsps: r.ocsps.clone(),
            crls: r.crls.clone(),
        }
    }
}

#[pymethods]
impl VriEntry {
    fn __repr__(&self) -> String {
        format!(
            "VriEntry(hash={:?}, certs={}, ocsps={}, crls={})",
            self.hash_key, self.num_certs, self.num_ocsps, self.num_crls,
        )
    }
}

// ── DssInfo ─────────────────────────────────────────────────────────────────

/// Document Security Store (DSS) information.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct DssInfo {
    /// Object number of the DSS dictionary.
    pub obj_num: Option<u32>,
    /// Number of top-level certificates.
    pub num_certs: usize,
    /// Number of top-level OCSP responses.
    pub num_ocsps: usize,
    /// Number of top-level CRLs.
    pub num_crls: usize,
    /// DER-encoded top-level certificates.
    pub certs: Vec<Vec<u8>>,
    /// DER-encoded top-level OCSP responses.
    pub ocsps: Vec<Vec<u8>>,
    /// DER-encoded top-level CRLs.
    pub crls: Vec<Vec<u8>>,
    /// Per-signature VRI entries.
    pub vri: Vec<VriEntry>,
}

impl DssInfo {
    fn from_rust(r: &RustDssInfo) -> Self {
        Self {
            obj_num: r.obj_num,
            num_certs: r.num_certs,
            num_ocsps: r.num_ocsps,
            num_crls: r.num_crls,
            certs: r.certs.clone(),
            ocsps: r.ocsps.clone(),
            crls: r.crls.clone(),
            vri: r.vri.iter().map(VriEntry::from_rust).collect(),
        }
    }
}

#[pymethods]
impl DssInfo {
    fn __repr__(&self) -> String {
        format!(
            "DssInfo(certs={}, ocsps={}, crls={}, vri={})",
            self.num_certs,
            self.num_ocsps,
            self.num_crls,
            self.vri.len(),
        )
    }
}

// ── RevisionInfo ────────────────────────────────────────────────────────────

/// A detected PDF revision (bounded by %%EOF).
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct RevisionInfo {
    /// 0-based index.
    pub index: usize,
    /// Byte offset of the %%EOF marker end.
    pub eof_offset: usize,
    /// Start byte of this revision's incremental section.
    pub byte_start: usize,
    /// End byte (after trailing newlines past %%EOF).
    pub byte_end: usize,
}

impl RevisionInfo {
    fn from_rust(r: &RustRevisionInfo) -> Self {
        Self {
            index: r.index,
            eof_offset: r.eof_offset,
            byte_start: r.byte_start,
            byte_end: r.byte_end,
        }
    }
}

#[pymethods]
impl RevisionInfo {
    fn __repr__(&self) -> String {
        format!(
            "RevisionInfo(index={}, start={}, end={})",
            self.index, self.byte_start, self.byte_end,
        )
    }
}

// ── PdfSignatureInspection ──────────────────────────────────────────────────

/// Result of inspecting a PDF's signature-related structures.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct PdfSignatureInspection {
    /// Whether the PDF has any signatures.
    pub has_signatures: bool,
    /// Number of signatures found.
    pub num_signatures: usize,
    /// Signature field details.
    pub signatures: Vec<SignatureFieldInfo>,
    /// Document Security Store, if present.
    pub dss: Option<DssInfo>,
    /// Detected revisions.
    pub revisions: Vec<RevisionInfo>,
    /// Total file size in bytes.
    pub file_size: usize,
}

impl PdfSignatureInspection {
    fn from_rust(r: &RustPdfSignatureInspection) -> Self {
        Self {
            has_signatures: r.has_signatures,
            num_signatures: r.num_signatures,
            signatures: r
                .signatures
                .iter()
                .map(SignatureFieldInfo::from_rust)
                .collect(),
            dss: r.dss.as_ref().map(DssInfo::from_rust),
            revisions: r.revisions.iter().map(RevisionInfo::from_rust).collect(),
            file_size: r.file_size,
        }
    }
}

#[pymethods]
impl PdfSignatureInspection {
    fn __repr__(&self) -> String {
        format!(
            "PdfSignatureInspection(has_signatures={}, num_signatures={}, file_size={})",
            self.has_signatures, self.num_signatures, self.file_size,
        )
    }
}

// ── Module functions ────────────────────────────────────────────────────────

/// Inspect all objects in a PDF.
///
/// Parses the PDF from raw bytes, enumerates every indirect object,
/// classifies it, and serializes its contents to Python-native types.
///
/// Args:
///     pdf_data: The PDF file contents as bytes.
///
/// Returns:
///     A PdfInspection with the full object tree.
///
/// Raises:
///     ValueError: If the PDF cannot be parsed.
#[pyfunction]
pub fn inspect_pdf(py: Python<'_>, pdf_data: Vec<u8>) -> PyResult<PdfInspection> {
    validate_pdf_input(&pdf_data)?;
    // Run the Rust inspection with GIL released, then convert to Python types
    let result = py.detach(|| {
        rust_inspect_pdf(&pdf_data).map_err(|e| PyValueError::new_err(format!("{e}")))
    })?;
    Ok(PdfInspection::from_rust(&result))
}

/// Inspect all signature-related data in a PDF.
///
/// Extracts signature fields, DSS (with full DER content), and revision info.
///
/// Args:
///     pdf_data: The PDF file contents as bytes.
///
/// Returns:
///     A PdfSignatureInspection with signature metadata and DSS.
///
/// Raises:
///     ValueError: If the PDF cannot be parsed.
#[pyfunction]
pub fn inspect_signatures(py: Python<'_>, pdf_data: Vec<u8>) -> PyResult<PdfSignatureInspection> {
    validate_pdf_input(&pdf_data)?;
    let result = py.detach(|| {
        rust_inspect_signatures(&pdf_data).map_err(|e| PyValueError::new_err(format!("{e}")))
    })?;
    Ok(PdfSignatureInspection::from_rust(&result))
}

/// Extract raw CMS/PKCS#7 bytes from a signature dictionary at the given object number.
///
/// Args:
///     pdf_data: The PDF file contents as bytes.
///     obj_num: The object number of the signature dictionary.
///
/// Returns:
///     The raw DER-encoded CMS SignedData bytes.
///
/// Raises:
///     ValueError: If the object cannot be found or has no /Contents.
#[pyfunction]
pub fn extract_cms_by_object(py: Python<'_>, pdf_data: Vec<u8>, obj_num: u32) -> PyResult<Vec<u8>> {
    validate_pdf_input(&pdf_data)?;
    py.detach(|| {
        rust_extract_cms_by_object(&pdf_data, obj_num)
            .map_err(|e| PyValueError::new_err(format!("{e}")))
    })
}
