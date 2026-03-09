//! Python bindings for the underskrift PDF signing and verification library.
//!
//! This crate provides PyO3 wrappers around the core underskrift types,
//! exposing signature verification, signing, trust management, and policy
//! evaluation to Python.

use pyo3::prelude::*;

mod crypto;
mod enums;
mod extractor;
mod policy;
mod remote;
mod signer;
mod trust;
mod verify;

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

    Ok(())
}
