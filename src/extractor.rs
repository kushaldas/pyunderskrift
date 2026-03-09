//! Signature extraction wrappers for Python.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use underskrift::verify::extractor::{
    extract_signatures as rust_extract_signatures, ExtractedSignature as RustExtractedSignature,
};

use crate::enums::SignatureType;

/// Metadata extracted from a PDF signature (without cryptographic verification).
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct ExtractedSignature {
    /// Name of the signature form field.
    pub field_name: String,
    /// Type of signature.
    pub signature_type: SignatureType,
    /// ByteRange as a list of 4 integers [offset1, len1, offset2, len2].
    pub byte_range: Vec<usize>,
    /// Raw CMS/PKCS#7 signature bytes.
    pub cms_bytes: Vec<u8>,
    /// Reason for signing, if specified.
    pub reason: Option<String>,
    /// Location of signing, if specified.
    pub location: Option<String>,
    /// Contact info of the signer, if specified.
    pub contact_info: Option<String>,
    /// Name of the signer, if specified.
    pub signer_name: Option<String>,
    /// Signing time from the signature dictionary.
    pub signing_time: Option<String>,
}

impl ExtractedSignature {
    fn from_rust(r: &RustExtractedSignature) -> Self {
        Self {
            field_name: r.field_name.clone(),
            signature_type: SignatureType::from(&r.signature_type),
            byte_range: r.byte_range.to_vec(),
            cms_bytes: r.cms_bytes.clone(),
            reason: r.reason.clone(),
            location: r.location.clone(),
            contact_info: r.contact_info.clone(),
            signer_name: r.signer_name.clone(),
            signing_time: r.signing_time.clone(),
        }
    }
}

#[pymethods]
impl ExtractedSignature {
    fn __repr__(&self) -> String {
        format!(
            "ExtractedSignature(field={:?}, type={:?}, signer={:?})",
            self.field_name, self.signature_type.kind, self.signer_name,
        )
    }
}

/// Extract signature metadata from a PDF without verifying them.
///
/// Args:
///     pdf_data: The PDF file contents as bytes.
///
/// Returns:
///     A list of ExtractedSignature objects.
///
/// Raises:
///     ValueError: If the PDF cannot be parsed.
#[pyfunction]
pub fn extract_signatures(py: Python<'_>, pdf_data: Vec<u8>) -> PyResult<Vec<ExtractedSignature>> {
    py.detach(|| {
        let sigs = rust_extract_signatures(&pdf_data)
            .map_err(|e| PyValueError::new_err(format!("{e}")))?;
        Ok(sigs.iter().map(ExtractedSignature::from_rust).collect())
    })
}
