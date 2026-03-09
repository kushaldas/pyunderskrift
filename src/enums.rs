//! Enum wrappers for Python.
//!
//! Simple enums use `#[pyclass(eq, eq_int)]` for int-style comparison.
//! Complex enums with associated data use struct wrappers with a `.kind` property.

use pyo3::prelude::*;

// ── Rust type aliases ──────────────────────────────────────────────────

use underskrift::cms::builder::SigningTimePlacement as RustSigningTimePlacement;
use underskrift::crypto::algorithm::{
    DigestAlgorithm as RustDigestAlgorithm, SignatureAlgorithm as RustSignatureAlgorithm,
};
use underskrift::ltv::status::{
    RevocationReason as RustRevocationReason, RevocationSource as RustRevocationSource,
    ValidationStatus as RustValidationStatus,
};
use underskrift::policy::PolicyConclusion as RustPolicyConclusion;
use underskrift::signer::{PadesLevel as RustPadesLevel, SubFilter as RustSubFilter};
use underskrift::trust::StoreKind as RustStoreKind;
use underskrift::verify::chain_verify::CertValidity as RustCertValidity;
use underskrift::verify::extractor::SignatureType as RustSignatureType;
use underskrift::verify::report::{
    CryptoValidity as RustCryptoValidity, DetectedPadesLevel as RustDetectedPadesLevel,
    SignatureStatus as RustSignatureStatus,
};

// ═══════════════════════════════════════════════════════════════════════
// Simple enums (int-style, no associated data)
// ═══════════════════════════════════════════════════════════════════════

/// Status of a verified signature.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SignatureStatus {
    Valid = 0,
    ValidButUntrusted = 1,
    Invalid = 2,
    Indeterminate = 3,
}

impl From<&RustSignatureStatus> for SignatureStatus {
    fn from(v: &RustSignatureStatus) -> Self {
        match v {
            RustSignatureStatus::Valid => Self::Valid,
            RustSignatureStatus::ValidButUntrusted => Self::ValidButUntrusted,
            RustSignatureStatus::Invalid => Self::Invalid,
            RustSignatureStatus::Indeterminate => Self::Indeterminate,
        }
    }
}

/// Detected PAdES conformance level.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DetectedPadesLevel {
    BB = 0,
    BT = 1,
    BLT = 2,
    BLTA = 3,
    NotPades = 4,
    Unknown = 5,
}

impl From<&RustDetectedPadesLevel> for DetectedPadesLevel {
    fn from(v: &RustDetectedPadesLevel) -> Self {
        match v {
            RustDetectedPadesLevel::BB => Self::BB,
            RustDetectedPadesLevel::BT => Self::BT,
            RustDetectedPadesLevel::BLT => Self::BLT,
            RustDetectedPadesLevel::BLTA => Self::BLTA,
            RustDetectedPadesLevel::NotPades => Self::NotPades,
            RustDetectedPadesLevel::Unknown => Self::Unknown,
        }
    }
}

/// PAdES conformance level for signing.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PadesLevel {
    BB = 0,
    BT = 1,
    BLT = 2,
    BLTA = 3,
}

impl From<PadesLevel> for RustPadesLevel {
    fn from(v: PadesLevel) -> Self {
        match v {
            PadesLevel::BB => Self::BB,
            PadesLevel::BT => Self::BT,
            PadesLevel::BLT => Self::BLT,
            PadesLevel::BLTA => Self::BLTA,
        }
    }
}

impl From<&RustPadesLevel> for PadesLevel {
    fn from(v: &RustPadesLevel) -> Self {
        match v {
            RustPadesLevel::BB => Self::BB,
            RustPadesLevel::BT => Self::BT,
            RustPadesLevel::BLT => Self::BLT,
            RustPadesLevel::BLTA => Self::BLTA,
        }
    }
}

/// Signature sub-filter type.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SubFilter {
    Pades = 0,
    Pkcs7 = 1,
}

impl From<SubFilter> for RustSubFilter {
    fn from(v: SubFilter) -> Self {
        match v {
            SubFilter::Pades => Self::Pades,
            SubFilter::Pkcs7 => Self::Pkcs7,
        }
    }
}

impl From<&RustSubFilter> for SubFilter {
    fn from(v: &RustSubFilter) -> Self {
        match v {
            RustSubFilter::Pades => Self::Pades,
            RustSubFilter::Pkcs7 => Self::Pkcs7,
        }
    }
}

/// Kind of trust store.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StoreKind {
    Signature = 0,
    Timestamp = 1,
    Svt = 2,
}

impl From<StoreKind> for RustStoreKind {
    fn from(v: StoreKind) -> Self {
        match v {
            StoreKind::Signature => Self::Signature,
            StoreKind::Timestamp => Self::Timestamp,
            StoreKind::Svt => Self::Svt,
        }
    }
}

impl From<&RustStoreKind> for StoreKind {
    fn from(v: &RustStoreKind) -> Self {
        match v {
            RustStoreKind::Signature => Self::Signature,
            RustStoreKind::Timestamp => Self::Timestamp,
            RustStoreKind::Svt => Self::Svt,
        }
    }
}

/// Policy evaluation conclusion.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PolicyConclusion {
    Passed = 0,
    Failed = 1,
    Indeterminate = 2,
}

impl From<&RustPolicyConclusion> for PolicyConclusion {
    fn from(v: &RustPolicyConclusion) -> Self {
        match v {
            RustPolicyConclusion::Passed => Self::Passed,
            RustPolicyConclusion::Failed => Self::Failed,
            RustPolicyConclusion::Indeterminate => Self::Indeterminate,
        }
    }
}

impl From<PolicyConclusion> for RustPolicyConclusion {
    fn from(v: PolicyConclusion) -> Self {
        match v {
            PolicyConclusion::Passed => Self::Passed,
            PolicyConclusion::Failed => Self::Failed,
            PolicyConclusion::Indeterminate => Self::Indeterminate,
        }
    }
}

/// Digest (hash) algorithm.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DigestAlgorithm {
    Sha256 = 0,
    Sha384 = 1,
    Sha512 = 2,
    Sha3_256 = 3,
    Sha3_384 = 4,
    Sha3_512 = 5,
}

impl From<DigestAlgorithm> for RustDigestAlgorithm {
    fn from(v: DigestAlgorithm) -> Self {
        match v {
            DigestAlgorithm::Sha256 => Self::Sha256,
            DigestAlgorithm::Sha384 => Self::Sha384,
            DigestAlgorithm::Sha512 => Self::Sha512,
            DigestAlgorithm::Sha3_256 => Self::Sha3_256,
            DigestAlgorithm::Sha3_384 => Self::Sha3_384,
            DigestAlgorithm::Sha3_512 => Self::Sha3_512,
        }
    }
}

impl From<&RustDigestAlgorithm> for DigestAlgorithm {
    fn from(v: &RustDigestAlgorithm) -> Self {
        match v {
            RustDigestAlgorithm::Sha256 => Self::Sha256,
            RustDigestAlgorithm::Sha384 => Self::Sha384,
            RustDigestAlgorithm::Sha512 => Self::Sha512,
            RustDigestAlgorithm::Sha3_256 => Self::Sha3_256,
            RustDigestAlgorithm::Sha3_384 => Self::Sha3_384,
            RustDigestAlgorithm::Sha3_512 => Self::Sha3_512,
        }
    }
}

#[pymethods]
impl DigestAlgorithm {
    /// Return the algorithm name (e.g. "SHA-256").
    fn name(&self) -> &'static str {
        let r: RustDigestAlgorithm = (*self).into();
        r.name()
    }
}

/// Signature algorithm.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SignatureAlgorithm {
    RsaPkcs1v15 = 0,
    RsaPss = 1,
    EcdsaP256 = 2,
    EcdsaP384 = 3,
    Ed25519 = 4,
}

impl From<SignatureAlgorithm> for RustSignatureAlgorithm {
    fn from(v: SignatureAlgorithm) -> Self {
        match v {
            SignatureAlgorithm::RsaPkcs1v15 => Self::RsaPkcs1v15,
            SignatureAlgorithm::RsaPss => Self::RsaPss,
            SignatureAlgorithm::EcdsaP256 => Self::EcdsaP256,
            SignatureAlgorithm::EcdsaP384 => Self::EcdsaP384,
            SignatureAlgorithm::Ed25519 => Self::Ed25519,
        }
    }
}

impl From<&RustSignatureAlgorithm> for SignatureAlgorithm {
    fn from(v: &RustSignatureAlgorithm) -> Self {
        match v {
            RustSignatureAlgorithm::RsaPkcs1v15 => Self::RsaPkcs1v15,
            RustSignatureAlgorithm::RsaPss => Self::RsaPss,
            RustSignatureAlgorithm::EcdsaP256 => Self::EcdsaP256,
            RustSignatureAlgorithm::EcdsaP384 => Self::EcdsaP384,
            RustSignatureAlgorithm::Ed25519 => Self::Ed25519,
        }
    }
}

#[pymethods]
impl SignatureAlgorithm {
    /// Return the algorithm name (e.g. "RSA-PKCS1-v1.5").
    fn name(&self) -> &'static str {
        let r: RustSignatureAlgorithm = (*self).into();
        r.name()
    }
}

/// Where to place the signingTime attribute.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SigningTimePlacement {
    Signed = 0,
    Unsigned = 1,
    Both = 2,
}

impl From<SigningTimePlacement> for RustSigningTimePlacement {
    fn from(v: SigningTimePlacement) -> Self {
        match v {
            SigningTimePlacement::Signed => Self::Signed,
            SigningTimePlacement::Unsigned => Self::Unsigned,
            SigningTimePlacement::Both => Self::Both,
        }
    }
}

impl From<&RustSigningTimePlacement> for SigningTimePlacement {
    fn from(v: &RustSigningTimePlacement) -> Self {
        match v {
            RustSigningTimePlacement::Signed => Self::Signed,
            RustSigningTimePlacement::Unsigned => Self::Unsigned,
            RustSigningTimePlacement::Both => Self::Both,
        }
    }
}

/// Source of a revocation check result.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RevocationSource {
    Crl = 0,
    Ocsp = 1,
}

impl From<&RustRevocationSource> for RevocationSource {
    fn from(v: &RustRevocationSource) -> Self {
        match v {
            RustRevocationSource::Crl => Self::Crl,
            RustRevocationSource::Ocsp => Self::Ocsp,
        }
    }
}

/// Revocation reason code per RFC 5280.
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

/// Convert a Rust RevocationReason to our Python wrapper.
///
/// Returns `None` for `Unknown(_)` variants that can't be represented as an int enum.
#[allow(dead_code)]
pub fn convert_revocation_reason(v: &RustRevocationReason) -> Option<RevocationReason> {
    match v {
        RustRevocationReason::Unspecified => Some(RevocationReason::Unspecified),
        RustRevocationReason::KeyCompromise => Some(RevocationReason::KeyCompromise),
        RustRevocationReason::CaCompromise => Some(RevocationReason::CaCompromise),
        RustRevocationReason::AffiliationChanged => Some(RevocationReason::AffiliationChanged),
        RustRevocationReason::Superseded => Some(RevocationReason::Superseded),
        RustRevocationReason::CessationOfOperation => Some(RevocationReason::CessationOfOperation),
        RustRevocationReason::CertificateHold => Some(RevocationReason::CertificateHold),
        RustRevocationReason::RemoveFromCrl => Some(RevocationReason::RemoveFromCrl),
        RustRevocationReason::PrivilegeWithdrawn => Some(RevocationReason::PrivilegeWithdrawn),
        RustRevocationReason::AaCompromise => Some(RevocationReason::AaCompromise),
        RustRevocationReason::Unknown(_) => None, // Can't represent in int enum
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Complex enums (struct-based, with .kind property + variant data)
// ═══════════════════════════════════════════════════════════════════════

/// Cryptographic validity of a signature.
///
/// `.kind` is one of: "valid", "invalid", "unknown_algorithm".
/// `.message` contains the error/algorithm string for non-valid variants.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct CryptoValidity {
    pub kind: String,
    pub message: Option<String>,
}

#[pymethods]
impl CryptoValidity {
    fn __repr__(&self) -> String {
        match &self.message {
            Some(msg) => format!("CryptoValidity(kind={:?}, message={:?})", self.kind, msg),
            None => format!("CryptoValidity(kind={:?})", self.kind),
        }
    }

    fn __str__(&self) -> String {
        match &self.message {
            Some(msg) => format!("{}: {}", self.kind, msg),
            None => self.kind.clone(),
        }
    }
}

impl From<&RustCryptoValidity> for CryptoValidity {
    fn from(v: &RustCryptoValidity) -> Self {
        match v {
            RustCryptoValidity::Valid => Self {
                kind: "valid".into(),
                message: None,
            },
            RustCryptoValidity::Invalid(msg) => Self {
                kind: "invalid".into(),
                message: Some(msg.clone()),
            },
            RustCryptoValidity::UnknownAlgorithm(alg) => Self {
                kind: "unknown_algorithm".into(),
                message: Some(alg.clone()),
            },
        }
    }
}

/// Certificate validity status.
///
/// `.kind` is one of: "valid", "expired", "not_yet_valid", "revoked",
/// "chain_incomplete", "untrusted_root", "validation_error".
/// `.message` contains the reason string for revoked/validation_error variants.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct CertValidity {
    pub kind: String,
    pub message: Option<String>,
}

#[pymethods]
impl CertValidity {
    fn __repr__(&self) -> String {
        match &self.message {
            Some(msg) => format!("CertValidity(kind={:?}, message={:?})", self.kind, msg),
            None => format!("CertValidity(kind={:?})", self.kind),
        }
    }

    fn __str__(&self) -> String {
        match &self.message {
            Some(msg) => format!("{}: {}", self.kind, msg),
            None => self.kind.clone(),
        }
    }
}

impl From<&RustCertValidity> for CertValidity {
    fn from(v: &RustCertValidity) -> Self {
        match v {
            RustCertValidity::Valid => Self {
                kind: "valid".into(),
                message: None,
            },
            RustCertValidity::Expired => Self {
                kind: "expired".into(),
                message: None,
            },
            RustCertValidity::NotYetValid => Self {
                kind: "not_yet_valid".into(),
                message: None,
            },
            RustCertValidity::Revoked(reason) => Self {
                kind: "revoked".into(),
                message: Some(reason.clone()),
            },
            RustCertValidity::ChainIncomplete => Self {
                kind: "chain_incomplete".into(),
                message: None,
            },
            RustCertValidity::UntrustedRoot => Self {
                kind: "untrusted_root".into(),
                message: None,
            },
            RustCertValidity::ValidationError(msg) => Self {
                kind: "validation_error".into(),
                message: Some(msg.clone()),
            },
        }
    }
}

/// Type of PDF signature.
///
/// `.kind` is one of: "pades", "pkcs7_detached", "pkcs7_sha1",
/// "doc_timestamp", "unknown".
/// `.value` contains the raw string for "unknown" variants.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct SignatureType {
    pub kind: String,
    pub value: Option<String>,
}

#[pymethods]
impl SignatureType {
    fn __repr__(&self) -> String {
        match &self.value {
            Some(v) => format!("SignatureType(kind={:?}, value={:?})", self.kind, v),
            None => format!("SignatureType(kind={:?})", self.kind),
        }
    }

    fn __str__(&self) -> String {
        match &self.value {
            Some(v) => format!("{}: {}", self.kind, v),
            None => self.kind.clone(),
        }
    }
}

impl From<&RustSignatureType> for SignatureType {
    fn from(v: &RustSignatureType) -> Self {
        match v {
            RustSignatureType::Pades => Self {
                kind: "pades".into(),
                value: None,
            },
            RustSignatureType::Pkcs7Detached => Self {
                kind: "pkcs7_detached".into(),
                value: None,
            },
            RustSignatureType::Pkcs7Sha1 => Self {
                kind: "pkcs7_sha1".into(),
                value: None,
            },
            RustSignatureType::DocTimestamp => Self {
                kind: "doc_timestamp".into(),
                value: None,
            },
            RustSignatureType::Unknown(s) => Self {
                kind: "unknown".into(),
                value: Some(s.clone()),
            },
        }
    }
}

/// Certificate revocation validation status (LTV).
///
/// `.kind` is one of: "valid", "revoked", "invalid", "unknown".
/// Additional properties depending on variant:
/// - valid: `.source`, `.checked_at`
/// - revoked: `.source`, `.reason`, `.reason_code`, `.revocation_time`
/// - invalid: `.message`
/// - unknown: `.message`
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct ValidationStatus {
    pub kind: String,
    /// RevocationSource as string ("CRL" or "OCSP"), for valid/revoked.
    pub source: Option<String>,
    /// ISO 8601 timestamp when check was performed, for valid.
    pub checked_at: Option<String>,
    /// Revocation reason as string, for revoked.
    pub reason: Option<String>,
    /// Revocation reason code, for revoked.
    pub reason_code: Option<u8>,
    /// ISO 8601 timestamp when certificate was revoked, for revoked.
    pub revocation_time: Option<String>,
    /// Error/explanation message, for invalid/unknown.
    pub message: Option<String>,
}

#[pymethods]
impl ValidationStatus {
    fn __repr__(&self) -> String {
        format!("ValidationStatus(kind={:?})", self.kind)
    }

    fn __str__(&self) -> String {
        match self.kind.as_str() {
            "valid" => format!("valid (via {})", self.source.as_deref().unwrap_or("?")),
            "revoked" => format!(
                "revoked: {} (via {})",
                self.reason.as_deref().unwrap_or("?"),
                self.source.as_deref().unwrap_or("?")
            ),
            "invalid" => format!("invalid: {}", self.message.as_deref().unwrap_or("?")),
            "unknown" => format!("unknown: {}", self.message.as_deref().unwrap_or("?")),
            other => other.to_string(),
        }
    }
}

impl From<&RustValidationStatus> for ValidationStatus {
    fn from(v: &RustValidationStatus) -> Self {
        match v {
            RustValidationStatus::Valid { source, checked_at } => Self {
                kind: "valid".into(),
                source: Some(source.to_string()),
                checked_at: Some(checked_at.to_rfc3339()),
                reason: None,
                reason_code: None,
                revocation_time: None,
                message: None,
            },
            RustValidationStatus::Revoked {
                source,
                reason,
                revocation_time,
            } => Self {
                kind: "revoked".into(),
                source: Some(source.to_string()),
                checked_at: None,
                reason: Some(reason.to_string()),
                reason_code: Some(reason.code()),
                revocation_time: Some(revocation_time.to_rfc3339()),
                message: None,
            },
            RustValidationStatus::Invalid { reason } => Self {
                kind: "invalid".into(),
                source: None,
                checked_at: None,
                reason: None,
                reason_code: None,
                revocation_time: None,
                message: Some(reason.clone()),
            },
            RustValidationStatus::Unknown { reason } => Self {
                kind: "unknown".into(),
                source: None,
                checked_at: None,
                reason: None,
                reason_code: None,
                revocation_time: None,
                message: Some(reason.clone()),
            },
        }
    }
}
