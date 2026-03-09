//! Cryptographic primitives wrappers for Python.

use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use underskrift::crypto::algorithm::{
    AlgorithmRegistry as RustAlgorithmRegistry, DigestAlgorithm as RustDigestAlgorithm,
    SignatureAlgorithm as RustSignatureAlgorithm,
};
use underskrift::crypto::software::SoftwareSigner as RustSoftwareSigner;
use underskrift::crypto::traits::CryptoSigner;

use crate::enums::{DigestAlgorithm, SignatureAlgorithm};

/// A software-based cryptographic signer using PKCS#12 or raw keys.
///
/// This type is NOT Clone — it's wrapped in Arc internally.
///
/// Example::
///
///     signer = SoftwareSigner.from_pkcs12_file("identity.p12", "password")
///     # Use with PdfSigner.sign()
#[pyclass(skip_from_py_object)]
pub struct SoftwareSigner {
    pub(crate) inner: Arc<RustSoftwareSigner>,
}

#[pymethods]
impl SoftwareSigner {
    /// Load a signer from a PKCS#12 (.p12/.pfx) file.
    ///
    /// Args:
    ///     path: Path to the PKCS#12 file.
    ///     password: Password to decrypt the file.
    #[staticmethod]
    fn from_pkcs12_file(path: &str, password: &str) -> PyResult<Self> {
        let signer = RustSoftwareSigner::from_pkcs12_file(path, password)
            .map_err(|e| PyValueError::new_err(format!("{e}")))?;
        Ok(Self {
            inner: Arc::new(signer),
        })
    }

    /// Load a signer from PKCS#12 data in memory.
    ///
    /// Args:
    ///     data: The PKCS#12 file contents as bytes.
    ///     password: Password to decrypt the data.
    #[staticmethod]
    fn from_pkcs12_data(data: Vec<u8>, password: &str) -> PyResult<Self> {
        let signer = RustSoftwareSigner::from_pkcs12_data(&data, password)
            .map_err(|e| PyValueError::new_err(format!("{e}")))?;
        Ok(Self {
            inner: Arc::new(signer),
        })
    }

    /// Get the signer's certificate in DER encoding.
    fn certificate_der(&self) -> Vec<u8> {
        self.inner.certificate_der().to_vec()
    }

    /// Get the certificate chain (excluding the signer cert) in DER encoding.
    fn certificate_chain_der(&self) -> Vec<Vec<u8>> {
        self.inner
            .certificate_chain_der()
            .iter()
            .map(|c| c.to_vec())
            .collect()
    }

    /// Get the digest algorithm used by this signer.
    fn digest_algorithm(&self) -> DigestAlgorithm {
        DigestAlgorithm::from(&self.inner.digest_algorithm())
    }

    /// Get the signature algorithm used by this signer.
    fn signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::from(&self.inner.signature_algorithm())
    }

    fn __repr__(&self) -> String {
        format!(
            "SoftwareSigner(digest={}, sig={})",
            self.inner.digest_algorithm().name(),
            self.inner.signature_algorithm().name(),
        )
    }
}

/// Registry of allowed cryptographic algorithms.
///
/// Used to restrict which algorithms are accepted during verification.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct AlgorithmRegistry {
    pub(crate) inner: RustAlgorithmRegistry,
}

#[pymethods]
impl AlgorithmRegistry {
    /// Create a new empty algorithm registry (no algorithms allowed).
    #[new]
    fn new() -> Self {
        Self {
            inner: RustAlgorithmRegistry::new(),
        }
    }

    /// Create a registry that allows all known algorithms.
    #[staticmethod]
    fn allow_all() -> Self {
        Self {
            inner: RustAlgorithmRegistry::allow_all(),
        }
    }

    /// Create a registry with the standard set of allowed algorithms.
    #[staticmethod]
    fn standard() -> Self {
        Self {
            inner: RustAlgorithmRegistry::standard(),
        }
    }

    /// Allow a specific digest algorithm.
    fn allow_digest(&mut self, alg: DigestAlgorithm) {
        let r: RustDigestAlgorithm = alg.into();
        self.inner = self.inner.clone().allow_digest(r);
    }

    /// Allow a specific signature algorithm.
    fn allow_signature(&mut self, alg: SignatureAlgorithm) {
        let r: RustSignatureAlgorithm = alg.into();
        self.inner = self.inner.clone().allow_signature(r);
    }

    fn __repr__(&self) -> String {
        "AlgorithmRegistry(...)".to_string()
    }
}
