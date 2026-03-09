//! Remote (three-phase) signing wrappers for Python.

use std::sync::Mutex;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use underskrift::remote::{
    finalize_signature as rust_finalize_signature, prepare_signature as rust_prepare_signature,
    PreparedSignature as RustPreparedSignature, RemoteSignerInfo as RustRemoteSignerInfo,
    RemoteSigningOptions as RustRemoteSigningOptions,
};

use crate::enums::{DigestAlgorithm, SignatureAlgorithm, SubFilter};

/// Information about the remote signer's certificate and algorithms.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct RemoteSignerInfo {
    /// Signer certificate in DER encoding.
    pub certificate_der: Vec<u8>,
    /// Certificate chain (excluding signer cert) in DER encoding.
    pub chain_der: Vec<Vec<u8>>,
    /// Digest algorithm to use.
    pub digest_algorithm: DigestAlgorithm,
    /// Signature algorithm to use.
    pub signature_algorithm: SignatureAlgorithm,
}

#[pymethods]
impl RemoteSignerInfo {
    #[new]
    fn new(
        certificate_der: Vec<u8>,
        chain_der: Vec<Vec<u8>>,
        digest_algorithm: DigestAlgorithm,
        signature_algorithm: SignatureAlgorithm,
    ) -> Self {
        Self {
            certificate_der,
            chain_der,
            digest_algorithm,
            signature_algorithm,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "RemoteSignerInfo(cert={} bytes, chain={} certs)",
            self.certificate_der.len(),
            self.chain_der.len(),
        )
    }
}

impl RemoteSignerInfo {
    fn to_rust(&self) -> RustRemoteSignerInfo {
        RustRemoteSignerInfo {
            certificate_der: self.certificate_der.clone(),
            chain_der: self.chain_der.clone(),
            digest_algorithm: self.digest_algorithm.into(),
            signature_algorithm: self.signature_algorithm.into(),
        }
    }
}

/// Options for remote signing.
#[pyclass(get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct RemoteSigningOptions {
    /// Signature sub-filter type.
    pub sub_filter: SubFilter,
    /// Digest algorithm.
    pub digest_algorithm: DigestAlgorithm,
    /// Signature field name.
    pub field_name: String,
    /// Page number for the signature (0-indexed).
    pub page: u32,
    /// Reason for signing.
    pub reason: Option<String>,
    /// Location of signing.
    pub location: Option<String>,
    /// Contact info of the signer.
    pub contact_info: Option<String>,
    /// Content size for the signature placeholder.
    pub content_size: usize,
}

#[pymethods]
impl RemoteSigningOptions {
    #[new]
    #[pyo3(signature = (
        sub_filter=SubFilter::Pades,
        digest_algorithm=DigestAlgorithm::Sha256,
        field_name="Signature1".to_string(),
        page=0,
        reason=None,
        location=None,
        contact_info=None,
        content_size=8192,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        sub_filter: SubFilter,
        digest_algorithm: DigestAlgorithm,
        field_name: String,
        page: u32,
        reason: Option<String>,
        location: Option<String>,
        contact_info: Option<String>,
        content_size: usize,
    ) -> Self {
        Self {
            sub_filter,
            digest_algorithm,
            field_name,
            page,
            reason,
            location,
            contact_info,
            content_size,
        }
    }

    fn __repr__(&self) -> String {
        format!("RemoteSigningOptions(field={:?})", self.field_name)
    }
}

impl RemoteSigningOptions {
    fn to_rust(&self) -> RustRemoteSigningOptions {
        RustRemoteSigningOptions {
            sub_filter: self.sub_filter.into(),
            digest_algorithm: self.digest_algorithm.into(),
            field_name: self.field_name.clone(),
            page: self.page,
            reason: self.reason.clone(),
            location: self.location.clone(),
            contact_info: self.contact_info.clone(),
            content_size: self.content_size,
            algorithm_registry: None,
        }
    }
}

/// Result from the first phase of three-phase signing.
///
/// Contains the hash that must be signed by the remote party.
#[pyclass(skip_from_py_object)]
pub struct PreparedSignature {
    inner: Mutex<Option<RustPreparedSignature>>,
    /// Cached attrs_hash for the getter (since inner may be taken).
    cached_attrs_hash: Vec<u8>,
}

#[pymethods]
impl PreparedSignature {
    /// The hash of the signed attributes that must be signed by the remote signer.
    #[getter]
    fn attrs_hash(&self) -> Vec<u8> {
        self.cached_attrs_hash.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "PreparedSignature(hash={} bytes)",
            self.cached_attrs_hash.len()
        )
    }
}

/// Phase 1 of three-phase remote signing: prepare a PDF for signing.
///
/// Returns a PreparedSignature containing the hash to be signed remotely.
///
/// Args:
///     pdf_data: The PDF file contents as bytes.
///     signer_info: Information about the remote signer.
///     options: Remote signing options.
///
/// Returns:
///     A PreparedSignature with the attrs_hash to sign.
///
/// Raises:
///     ValueError: If preparation fails.
#[pyfunction]
pub fn prepare_signature(
    py: Python<'_>,
    pdf_data: Vec<u8>,
    signer_info: &RemoteSignerInfo,
    options: &RemoteSigningOptions,
) -> PyResult<PreparedSignature> {
    let rust_info = signer_info.to_rust();
    let rust_opts = options.to_rust();

    py.detach(|| {
        let prepared = rust_prepare_signature(&pdf_data, &rust_info, &rust_opts)
            .map_err(|e| PyValueError::new_err(format!("{e}")))?;
        let cached_hash = prepared.attrs_hash.clone();
        Ok(PreparedSignature {
            inner: Mutex::new(Some(prepared)),
            cached_attrs_hash: cached_hash,
        })
    })
}

/// Phase 3 of three-phase remote signing: finalize a signed PDF.
///
/// Takes the prepared signature and the actual signature bytes from the
/// remote signer, and produces the final signed PDF.
///
/// Note: This consumes the PreparedSignature — calling it a second time
/// will raise ValueError.
///
/// Args:
///     prepared: The PreparedSignature from phase 1.
///     signature_bytes: The raw signature bytes from the remote signer.
///
/// Returns:
///     The signed PDF as bytes.
///
/// Raises:
///     ValueError: If finalization fails or PreparedSignature was already consumed.
#[pyfunction]
pub fn finalize_signature(
    py: Python<'_>,
    prepared: &PreparedSignature,
    signature_bytes: Vec<u8>,
) -> PyResult<Vec<u8>> {
    // Take ownership of the inner PreparedSignature via the Mutex.
    let rust_prepared = prepared
        .inner
        .lock()
        .map_err(|e| PyValueError::new_err(format!("lock poisoned: {e}")))?
        .take()
        .ok_or_else(|| {
            PyValueError::new_err(
                "PreparedSignature has already been consumed by a previous finalize_signature call",
            )
        })?;

    py.detach(|| {
        rust_finalize_signature(rust_prepared, &signature_bytes)
            .map_err(|e| PyValueError::new_err(format!("{e}")))
    })
}
