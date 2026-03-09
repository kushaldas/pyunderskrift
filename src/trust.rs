//! Trust store wrappers for Python.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use underskrift::trust::TrustStore as RustTrustStore;
use underskrift::trust::{StoreKind as RustStoreKind, TrustStoreSet as RustTrustStoreSet};

use crate::enums::StoreKind;

/// A collection of trusted CA certificates.
///
/// Used to establish trust chains for signature verification.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct TrustStore {
    pub(crate) inner: RustTrustStore,
}

#[pymethods]
impl TrustStore {
    /// Create a new empty trust store.
    #[new]
    #[pyo3(signature = (label=None))]
    fn new(label: Option<String>) -> Self {
        let mut store = RustTrustStore::new();
        if let Some(l) = label {
            store = store.with_label(l);
        }
        Self { inner: store }
    }

    /// Load trust anchors from a PEM file.
    #[staticmethod]
    fn from_pem_file(path: &str) -> PyResult<Self> {
        let store = RustTrustStore::from_pem_file(path)
            .map_err(|e| PyValueError::new_err(format!("{e}")))?;
        Ok(Self { inner: store })
    }

    /// Load trust anchors from all PEM files in a directory.
    #[staticmethod]
    fn from_pem_directory(path: &str) -> PyResult<Self> {
        let store = RustTrustStore::from_pem_directory(path)
            .map_err(|e| PyValueError::new_err(format!("{e}")))?;
        Ok(Self { inner: store })
    }

    /// Add a DER-encoded certificate to the store.
    fn add_der_certificate(&mut self, der: Vec<u8>) -> PyResult<()> {
        self.inner
            .add_der_certificate(&der)
            .map_err(|e| PyValueError::new_err(format!("{e}")))
    }

    /// Add PEM-encoded certificate data (may contain multiple certificates).
    fn add_pem_data(&mut self, pem_data: Vec<u8>) -> PyResult<()> {
        self.inner
            .add_pem_data(&pem_data)
            .map_err(|e| PyValueError::new_err(format!("{e}")))
    }

    /// Check if the store contains a certificate with the given DER encoding.
    fn contains_der(&self, cert_der: Vec<u8>) -> bool {
        self.inner.contains_der(&cert_der)
    }

    /// Number of certificates in the store.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get the store label, if any.
    #[getter]
    fn label(&self) -> Option<String> {
        self.inner.label().map(|s| s.to_string())
    }

    /// Return all certificates as a list of DER-encoded bytes.
    fn certificates_der(&self) -> Vec<Vec<u8>> {
        self.inner.certificates_der().map(|d| d.to_vec()).collect()
    }

    fn __repr__(&self) -> String {
        let label = self.inner.label().unwrap_or("(unlabeled)");
        format!("TrustStore({:?}, {} certs)", label, self.inner.len())
    }
}

/// A set of trust stores for different purposes (signature, TSA, SVT).
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct TrustStoreSet {
    pub(crate) inner: RustTrustStoreSet,
}

#[pymethods]
impl TrustStoreSet {
    /// Create a new empty trust store set.
    #[new]
    fn new() -> Self {
        Self {
            inner: RustTrustStoreSet::new(),
        }
    }

    /// Set the signature verification trust store.
    fn set_sig_store(&mut self, store: &TrustStore) {
        self.inner = self.inner.clone().with_sig_store(store.inner.clone());
    }

    /// Set the timestamp verification trust store.
    fn set_tsa_store(&mut self, store: &TrustStore) {
        self.inner = self.inner.clone().with_tsa_store(store.inner.clone());
    }

    /// Set the SVT verification trust store.
    fn set_svt_store(&mut self, store: &TrustStore) {
        self.inner = self.inner.clone().with_svt_store(store.inner.clone());
    }

    /// Get a trust store by kind. Returns None if not set.
    fn get(&self, kind: StoreKind) -> Option<TrustStore> {
        let rk: RustStoreKind = kind.into();
        self.inner.get(rk).map(|s| TrustStore { inner: s.clone() })
    }

    /// Whether any trust store is set.
    fn has_any(&self) -> bool {
        self.inner.has_any()
    }

    fn __repr__(&self) -> String {
        let sig = self.inner.sig().map(|s| s.len()).unwrap_or(0);
        let tsa = self.inner.tsa().map(|s| s.len()).unwrap_or(0);
        let svt = self.inner.svt().map(|s| s.len()).unwrap_or(0);
        format!("TrustStoreSet(sig={sig} certs, tsa={tsa} certs, svt={svt} certs)")
    }
}
