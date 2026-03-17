//! Python bindings for the underskrift PDF signing and verification library.
//!
//! This crate provides PyO3 wrappers around the core underskrift types,
//! exposing signature verification, signing, trust management, and policy
//! evaluation to Python.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

mod crypto;
mod enums;
mod extractor;
mod inspect;
mod policy;
mod remote;
mod signer;
mod trust;
mod verify;

/// Maximum PDF size accepted by the Python bindings (256 MB).
const MAX_PDF_SIZE: usize = 256 * 1024 * 1024;

/// Validate PDF input data: non-empty, within size limit, starts with %PDF-.
pub(crate) fn validate_pdf_input(pdf_data: &[u8]) -> PyResult<()> {
    if pdf_data.is_empty() {
        return Err(PyValueError::new_err("PDF data is empty"));
    }
    if pdf_data.len() > MAX_PDF_SIZE {
        return Err(PyValueError::new_err(format!(
            "PDF data exceeds maximum size ({} bytes > {} bytes)",
            pdf_data.len(),
            MAX_PDF_SIZE
        )));
    }
    if pdf_data.len() < 5 || &pdf_data[..5] != b"%PDF-" {
        return Err(PyValueError::new_err(
            "Data does not start with PDF header (%PDF-)",
        ));
    }
    Ok(())
}

/// pyunderskrift — Python bindings for PDF signing and verification.
#[pymodule]
fn pyunderskrift(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Enums (simple int-style)
    m.add_class::<enums::SignatureStatus>()?;
    m.add_class::<enums::DetectedPadesLevel>()?;
    m.add_class::<enums::PadesLevel>()?;
    m.add_class::<enums::SubFilter>()?;
    m.add_class::<enums::StoreKind>()?;
    m.add_class::<enums::PolicyConclusion>()?;
    m.add_class::<enums::DigestAlgorithm>()?;
    m.add_class::<enums::SignatureAlgorithm>()?;
    m.add_class::<enums::SigningTimePlacement>()?;
    m.add_class::<enums::RevocationSource>()?;
    m.add_class::<enums::RevocationReason>()?;

    // Enums (complex, string-based)
    m.add_class::<enums::CryptoValidity>()?;
    m.add_class::<enums::CertValidity>()?;
    m.add_class::<enums::SignatureType>()?;
    m.add_class::<enums::ValidationStatus>()?;

    // Trust
    m.add_class::<trust::TrustStore>()?;
    m.add_class::<trust::TrustStoreSet>()?;

    // Verification
    m.add_class::<verify::SignatureVerifier>()?;
    m.add_class::<verify::VerificationReport>()?;
    m.add_class::<verify::SignatureVerificationResult>()?;

    // Policy
    m.add_class::<policy::PolicyCheckResult>()?;
    m.add_class::<policy::PolicyResult>()?;
    m.add_class::<policy::BasicPdfSignaturePolicy>()?;
    m.add_class::<policy::PkixPdfSignaturePolicy>()?;

    // Extractor
    m.add_class::<extractor::ExtractedSignature>()?;
    m.add_function(wrap_pyfunction!(extractor::extract_signatures, m)?)?;

    // Crypto
    m.add_class::<crypto::SoftwareSigner>()?;
    m.add_class::<crypto::AlgorithmRegistry>()?;

    // Signer
    m.add_class::<signer::PdfSigner>()?;
    m.add_class::<signer::SigningOptions>()?;

    // Remote signing
    m.add_class::<remote::RemoteSignerInfo>()?;
    m.add_class::<remote::RemoteSigningOptions>()?;
    m.add_class::<remote::PreparedSignature>()?;
    m.add_function(wrap_pyfunction!(remote::prepare_signature, m)?)?;
    m.add_function(wrap_pyfunction!(remote::finalize_signature, m)?)?;

    // Inspect
    m.add_class::<inspect::ObjectKind>()?;
    m.add_class::<inspect::PdfObjectInfo>()?;
    m.add_class::<inspect::PdfInspection>()?;
    m.add_class::<inspect::CoverageInfo>()?;
    m.add_class::<inspect::SignatureFieldInfo>()?;
    m.add_class::<inspect::VriEntry>()?;
    m.add_class::<inspect::DssInfo>()?;
    m.add_class::<inspect::RevisionInfo>()?;
    m.add_class::<inspect::PdfSignatureInspection>()?;
    m.add_function(wrap_pyfunction!(inspect::inspect_pdf, m)?)?;
    m.add_function(wrap_pyfunction!(inspect::inspect_signatures, m)?)?;
    m.add_function(wrap_pyfunction!(inspect::extract_cms_by_object, m)?)?;

    Ok(())
}
