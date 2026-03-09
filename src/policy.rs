//! Policy wrappers for Python.

use pyo3::prelude::*;

use underskrift::policy::{
    PolicyCheckResult as RustPolicyCheckResult, PolicyResult as RustPolicyResult,
};

use crate::enums::PolicyConclusion;

/// Result of a single policy check.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct PolicyCheckResult {
    /// Name of the check.
    pub check_name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Optional message with details.
    pub message: Option<String>,
}

impl PolicyCheckResult {
    pub(crate) fn from_rust(r: &RustPolicyCheckResult) -> Self {
        Self {
            check_name: r.check_name.to_string(),
            passed: r.passed,
            message: r.message.clone(),
        }
    }
}

#[pymethods]
impl PolicyCheckResult {
    fn __repr__(&self) -> String {
        format!(
            "PolicyCheckResult({:?}, passed={})",
            self.check_name, self.passed
        )
    }
}

/// Result of policy evaluation for a signature.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct PolicyResult {
    /// Identifier of the policy that was applied.
    pub policy_id: String,
    /// Overall conclusion of the policy evaluation.
    pub conclusion: PolicyConclusion,
    /// Optional summary message.
    pub message: Option<String>,
    /// Individual check results.
    pub checks: Vec<PolicyCheckResult>,
}

impl PolicyResult {
    pub(crate) fn from_rust(r: &RustPolicyResult) -> Self {
        Self {
            policy_id: r.policy_id.clone(),
            conclusion: PolicyConclusion::from(&r.conclusion),
            message: r.message.clone(),
            checks: r.checks.iter().map(PolicyCheckResult::from_rust).collect(),
        }
    }
}

#[pymethods]
impl PolicyResult {
    fn __repr__(&self) -> String {
        format!(
            "PolicyResult(policy={:?}, conclusion={:?}, checks={})",
            self.policy_id,
            format!("{:?}", self.conclusion),
            self.checks.len()
        )
    }
}

/// Basic PDF signature validation policy.
///
/// Checks that signatures are cryptographically valid and optionally
/// that no modifications were made after signing.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct BasicPdfSignaturePolicy {
    pub require_no_modifications: bool,
}

#[pymethods]
impl BasicPdfSignaturePolicy {
    #[new]
    #[pyo3(signature = (require_no_modifications=true))]
    fn new(require_no_modifications: bool) -> Self {
        Self {
            require_no_modifications,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "BasicPdfSignaturePolicy(require_no_modifications={})",
            self.require_no_modifications
        )
    }
}

/// PKIX-based PDF signature validation policy.
///
/// Performs thorough validation including certificate chain checking,
/// revocation status, timestamp verification, and time-based constraints.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct PkixPdfSignaturePolicy {
    /// Grace period in seconds for certificate expiration. Default: 86400 (24h).
    pub grace_period_secs: u64,
    /// Whether a definitive revocation result is required. Default: true.
    pub require_revocation_check: bool,
    /// Whether to reject signatures with post-signing modifications. Default: true.
    pub require_no_modifications: bool,
    /// Whether to enforce current-time certificate validity. Default: false.
    pub enforce_current_time_validation: bool,
    /// Whether to use timestamp time for validation. Default: true.
    pub use_timestamp_time: bool,
}

#[pymethods]
impl PkixPdfSignaturePolicy {
    #[new]
    #[pyo3(signature = (
        grace_period_secs=86400,
        require_revocation_check=true,
        require_no_modifications=true,
        enforce_current_time_validation=false,
        use_timestamp_time=true,
    ))]
    fn new(
        grace_period_secs: u64,
        require_revocation_check: bool,
        require_no_modifications: bool,
        enforce_current_time_validation: bool,
        use_timestamp_time: bool,
    ) -> Self {
        Self {
            grace_period_secs,
            require_revocation_check,
            require_no_modifications,
            enforce_current_time_validation,
            use_timestamp_time,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "PkixPdfSignaturePolicy(grace={}s, revocation={}, modifications={}, current_time={}, timestamp={})",
            self.grace_period_secs,
            self.require_revocation_check,
            self.require_no_modifications,
            self.enforce_current_time_validation,
            self.use_timestamp_time,
        )
    }
}
