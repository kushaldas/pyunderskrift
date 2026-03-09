//! Signature verification wrappers for Python.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use underskrift::policy::SignatureValidationPolicy;
use underskrift::verify::report::{
    SignatureVerificationResult as RustSignatureVerificationResult,
    VerificationReport as RustVerificationReport,
};
use underskrift::verify::SignatureVerifier as RustSignatureVerifier;

use crate::enums::{
    CertValidity, CryptoValidity, DetectedPadesLevel, SignatureStatus, SignatureType,
    ValidationStatus,
};
use crate::policy::{BasicPdfSignaturePolicy, PkixPdfSignaturePolicy, PolicyResult};
use crate::trust::TrustStoreSet;

/// Verifier for PDF digital signatures.
///
/// Owns a `TrustStoreSet` and creates the underlying Rust `SignatureVerifier`
/// on each call to `verify_pdf()` (because the Rust type has a lifetime
/// parameter tied to the trust stores).
///
/// Example::
///
///     store = TrustStore.from_pem_file("ca.pem")
///     stores = TrustStoreSet()
///     stores.set_sig_store(store)
///     verifier = SignatureVerifier(stores)
///     report = verifier.verify_pdf(pdf_bytes)
///     print(report.summary)
#[pyclass(skip_from_py_object)]
pub struct SignatureVerifier {
    trust_stores: underskrift::trust::TrustStoreSet,
    allow_online: bool,
    /// Stored policy choice: None, "basic", or "pkix" with serialized config.
    policy_choice: Option<PolicyChoice>,
}

/// Internal enum to track which policy the user set.
/// We can't store `Box<dyn SignatureValidationPolicy>` across calls easily,
/// so we store the configuration and reconstruct the policy object each time.
#[derive(Clone)]
enum PolicyChoice {
    Basic {
        require_no_modifications: bool,
    },
    Pkix {
        grace_period_secs: u64,
        require_revocation_check: bool,
        require_no_modifications: bool,
        enforce_current_time_validation: bool,
        use_timestamp_time: bool,
    },
}

impl PolicyChoice {
    fn to_boxed(&self) -> Box<dyn SignatureValidationPolicy> {
        match self {
            PolicyChoice::Basic {
                require_no_modifications,
            } => Box::new(
                underskrift::policy::basic::BasicPdfSignaturePolicy::new()
                    .require_no_modifications(*require_no_modifications),
            ),
            PolicyChoice::Pkix {
                grace_period_secs,
                require_revocation_check,
                require_no_modifications,
                enforce_current_time_validation,
                use_timestamp_time,
            } => Box::new(
                underskrift::policy::pkix::PkixPdfSignaturePolicy::new()
                    .grace_period(std::time::Duration::from_secs(*grace_period_secs))
                    .require_revocation_check(*require_revocation_check)
                    .require_no_modifications(*require_no_modifications)
                    .enforce_current_time_validation(*enforce_current_time_validation)
                    .use_timestamp_time(*use_timestamp_time),
            ),
        }
    }
}

#[pymethods]
impl SignatureVerifier {
    /// Create a new signature verifier with the given trust stores.
    #[new]
    #[pyo3(signature = (trust_stores, allow_online=false))]
    fn new(trust_stores: &TrustStoreSet, allow_online: bool) -> Self {
        Self {
            trust_stores: trust_stores.inner.clone(),
            allow_online,
            policy_choice: None,
        }
    }

    /// Set whether online validation (OCSP/CRL fetching) is allowed.
    fn set_allow_online(&mut self, allow: bool) {
        self.allow_online = allow;
    }

    /// Set a basic PDF signature validation policy.
    fn set_basic_policy(&mut self, policy: &BasicPdfSignaturePolicy) {
        self.policy_choice = Some(PolicyChoice::Basic {
            require_no_modifications: policy.require_no_modifications,
        });
    }

    /// Set a PKIX-based PDF signature validation policy.
    fn set_pkix_policy(&mut self, policy: &PkixPdfSignaturePolicy) {
        self.policy_choice = Some(PolicyChoice::Pkix {
            grace_period_secs: policy.grace_period_secs,
            require_revocation_check: policy.require_revocation_check,
            require_no_modifications: policy.require_no_modifications,
            enforce_current_time_validation: policy.enforce_current_time_validation,
            use_timestamp_time: policy.use_timestamp_time,
        });
    }

    /// Clear any set policy.
    fn clear_policy(&mut self) {
        self.policy_choice = None;
    }

    /// Verify all signatures in a PDF document.
    ///
    /// Args:
    ///     pdf_data: The PDF file contents as bytes.
    ///
    /// Returns:
    ///     A VerificationReport with details of each signature.
    ///
    /// Raises:
    ///     ValueError: If verification fails due to parsing errors.
    fn verify_pdf(&self, py: Python<'_>, pdf_data: Vec<u8>) -> PyResult<VerificationReport> {
        // Clone what we need before detaching from the GIL
        let trust_stores = self.trust_stores.clone();
        let allow_online = self.allow_online;
        let policy_choice = self.policy_choice.clone();

        py.detach(|| {
            let mut verifier = RustSignatureVerifier::new(&trust_stores).allow_online(allow_online);

            if let Some(ref choice) = policy_choice {
                verifier = verifier.policy(choice.to_boxed());
            }

            let report = verifier
                .verify_pdf(&pdf_data)
                .map_err(|e| PyValueError::new_err(format!("{e}")))?;

            Ok(VerificationReport::from_rust(report))
        })
    }

    fn __repr__(&self) -> String {
        let policy = match &self.policy_choice {
            None => "none",
            Some(PolicyChoice::Basic { .. }) => "basic",
            Some(PolicyChoice::Pkix { .. }) => "pkix",
        };
        format!(
            "SignatureVerifier(online={}, policy={:?})",
            self.allow_online, policy
        )
    }
}

/// Report from verifying all signatures in a PDF document.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct VerificationReport {
    /// Individual signature verification results.
    pub signatures: Vec<SignatureVerificationResult>,
    /// Whether the document has been modified after the last signature.
    pub document_modified: bool,
    /// Number of valid signatures.
    pub valid_count: usize,
    /// Number of invalid signatures.
    pub invalid_count: usize,
    /// Number of signatures that passed policy evaluation.
    pub policy_passed_count: usize,
    /// Number of signatures that failed policy evaluation.
    pub policy_failed_count: usize,
    /// Number of signatures with indeterminate policy evaluation.
    pub policy_indeterminate_count: usize,
    /// Human-readable summary of the verification.
    pub summary: String,
}

impl VerificationReport {
    fn from_rust(r: RustVerificationReport) -> Self {
        Self {
            signatures: r
                .signatures
                .iter()
                .map(SignatureVerificationResult::from_rust)
                .collect(),
            document_modified: r.document_modified,
            valid_count: r.valid_count,
            invalid_count: r.invalid_count,
            policy_passed_count: r.policy_passed_count,
            policy_failed_count: r.policy_failed_count,
            policy_indeterminate_count: r.policy_indeterminate_count,
            summary: r.summary.clone(),
        }
    }
}

#[pymethods]
impl VerificationReport {
    /// Whether all signatures are cryptographically valid.
    fn all_valid(&self) -> bool {
        self.invalid_count == 0 && self.valid_count > 0
    }

    /// Whether at least one signature is valid.
    fn any_valid(&self) -> bool {
        self.valid_count > 0
    }

    fn __repr__(&self) -> String {
        format!(
            "VerificationReport(valid={}, invalid={}, modified={})",
            self.valid_count, self.invalid_count, self.document_modified
        )
    }

    fn __str__(&self) -> &str {
        &self.summary
    }

    fn __len__(&self) -> usize {
        self.signatures.len()
    }
}

/// Detailed result of verifying a single PDF signature.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct SignatureVerificationResult {
    /// Name of the signature form field.
    pub field_name: String,
    /// Overall signature status.
    pub status: SignatureStatus,
    /// Type of signature (PAdES, PKCS#7, etc.).
    pub signature_type: SignatureType,
    /// Name of the signer, if available.
    pub signer_name: Option<String>,
    /// Signing time from the signature dictionary (string).
    pub signing_time: Option<String>,
    /// CMS signing time attribute (ISO 8601 string).
    pub cms_signing_time: Option<String>,
    /// Timestamp time from a timestamp token (string).
    pub timestamp_time: Option<String>,
    /// Whether ESS-cert-id matches the signer certificate.
    pub ess_cert_id_match: Option<bool>,
    /// Validation time actually used (ISO 8601 string).
    pub validation_time_used: Option<String>,
    /// Whether the signature is cryptographically intact.
    pub integrity_ok: bool,
    /// Whether the signature covers the whole document.
    pub covers_whole_document: bool,
    /// List of integrity issues found.
    pub integrity_issues: Vec<String>,
    /// Cryptographic validity of the signature value.
    pub cryptographic_validity: CryptoValidity,
    /// Whether the signed data digest matches.
    pub digest_matches: bool,
    /// Certificate validity status.
    pub certificate_validity: CertValidity,
    /// Whether the certificate chain is trusted.
    pub chain_trusted: bool,
    /// Subject of the trust anchor certificate, if found.
    pub trust_anchor: Option<String>,
    /// Revocation status (LTV), if checked.
    pub revocation_status: Option<ValidationStatus>,
    /// Per-certificate revocation status: list of (subject, status) tuples.
    pub per_cert_revocation: Vec<(String, ValidationStatus)>,
    /// Detected PAdES conformance level.
    pub pades_level: DetectedPadesLevel,
    /// Whether modifications were made after signing.
    pub modifications_after_signing: bool,
    /// Whether the signature covers the whole document revision.
    pub covers_whole_document_revision: Option<bool>,
    /// Whether the document was extended by non-safe incremental updates.
    pub extended_by_non_safe_updates: Option<bool>,
    /// Policy evaluation result, if a policy was set.
    pub policy_result: Option<PolicyResult>,
    /// Signer certificate in DER encoding.
    pub signer_cert_der: Option<Vec<u8>>,
    /// Certificate chain in DER encoding.
    pub chain_certs_der: Vec<Vec<u8>>,
    /// Raw signature value bytes.
    pub signature_value_bytes: Vec<u8>,
    /// Hash of the data-to-be-signed representation.
    pub dtbsr_hash: Vec<u8>,
    /// OID of the signature algorithm used.
    pub signature_algorithm_oid: Option<String>,
    /// Timestamp token in DER encoding, if present.
    pub timestamp_token_der: Option<Vec<u8>>,
    /// Human-readable summary of this signature result.
    pub summary: String,
}

impl SignatureVerificationResult {
    fn from_rust(r: &RustSignatureVerificationResult) -> Self {
        Self {
            field_name: r.field_name.clone(),
            status: SignatureStatus::from(&r.status),
            signature_type: SignatureType::from(&r.signature_type),
            signer_name: r.signer_name.clone(),
            signing_time: r.signing_time.clone(),
            cms_signing_time: r.cms_signing_time.map(|dt| dt.to_rfc3339()),
            timestamp_time: r.timestamp_time.clone(),
            ess_cert_id_match: r.ess_cert_id_match,
            validation_time_used: r.validation_time_used.map(|dt| dt.to_rfc3339()),
            integrity_ok: r.integrity_ok,
            covers_whole_document: r.covers_whole_document,
            integrity_issues: r.integrity_issues.clone(),
            cryptographic_validity: CryptoValidity::from(&r.cryptographic_validity),
            digest_matches: r.digest_matches,
            certificate_validity: CertValidity::from(&r.certificate_validity),
            chain_trusted: r.chain_trusted,
            trust_anchor: r.trust_anchor.clone(),
            revocation_status: r.revocation_status.as_ref().map(ValidationStatus::from),
            per_cert_revocation: r
                .per_cert_revocation
                .iter()
                .map(|(subject, status)| (subject.clone(), ValidationStatus::from(status)))
                .collect(),
            pades_level: DetectedPadesLevel::from(&r.pades_level),
            modifications_after_signing: r.modifications_after_signing,
            covers_whole_document_revision: r.covers_whole_document_revision,
            extended_by_non_safe_updates: r.extended_by_non_safe_updates,
            policy_result: r.policy_result.as_ref().map(PolicyResult::from_rust),
            signer_cert_der: r.signer_cert_der.clone(),
            chain_certs_der: r.chain_certs_der.clone(),
            signature_value_bytes: r.signature_value_bytes.clone(),
            dtbsr_hash: r.dtbsr_hash.clone(),
            signature_algorithm_oid: r.signature_algorithm_oid.clone(),
            timestamp_token_der: r.timestamp_token_der.clone(),
            summary: r.summary.clone(),
        }
    }
}

#[pymethods]
impl SignatureVerificationResult {
    fn __repr__(&self) -> String {
        format!(
            "SignatureVerificationResult(field={:?}, status={:?}, signer={:?})",
            self.field_name,
            format!("{:?}", self.status),
            self.signer_name,
        )
    }

    fn __str__(&self) -> &str {
        &self.summary
    }
}
