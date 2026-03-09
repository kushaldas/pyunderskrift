//! PdfSigner and SigningOptions wrappers for Python.

use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

use underskrift::signer::{
    PdfSigner as RustPdfSigner,
    SigningOptions as RustSigningOptions,
};

use crate::crypto::{AlgorithmRegistry, SoftwareSigner};
use crate::enums::{DigestAlgorithm, PadesLevel, SigningTimePlacement, SubFilter};

/// Options controlling how a PDF is signed.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SigningOptions {
    pub(crate) sub_filter: SubFilter,
    pub(crate) pades_level: PadesLevel,
    pub(crate) digest_algorithm: DigestAlgorithm,
    pub(crate) field_name: String,
    pub(crate) page: u32,
    pub(crate) reason: Option<String>,
    pub(crate) location: Option<String>,
    pub(crate) contact_info: Option<String>,
    pub(crate) content_size: usize,
    pub(crate) tsa_url: Option<String>,
    pub(crate) certify: bool,
    pub(crate) algorithm_registry: Option<AlgorithmRegistry>,
    pub(crate) signing_time_placement: SigningTimePlacement,
}

#[pymethods]
impl SigningOptions {
    /// Create signing options with defaults.
    ///
    /// Defaults to PAdES B-B, SHA-256, auto-generated field name.
    #[new]
    #[pyo3(signature = (
        sub_filter=SubFilter::Pades,
        pades_level=PadesLevel::BB,
        digest_algorithm=DigestAlgorithm::Sha256,
        field_name=None,
        page=0,
        reason=None,
        location=None,
        contact_info=None,
        content_size=8192,
        tsa_url=None,
        certify=false,
        algorithm_registry=None,
        signing_time_placement=SigningTimePlacement::Signed,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        sub_filter: SubFilter,
        pades_level: PadesLevel,
        digest_algorithm: DigestAlgorithm,
        field_name: Option<String>,
        page: u32,
        reason: Option<String>,
        location: Option<String>,
        contact_info: Option<String>,
        content_size: usize,
        tsa_url: Option<String>,
        certify: bool,
        algorithm_registry: Option<&AlgorithmRegistry>,
        signing_time_placement: SigningTimePlacement,
    ) -> Self {
        Self {
            sub_filter,
            pades_level,
            digest_algorithm,
            field_name: field_name.unwrap_or_default(),
            page,
            reason,
            location,
            contact_info,
            content_size,
            tsa_url,
            certify,
            algorithm_registry: algorithm_registry.cloned(),
            signing_time_placement,
        }
    }

    // Getters
    #[getter]
    fn sub_filter(&self) -> SubFilter { self.sub_filter }
    #[getter]
    fn pades_level(&self) -> PadesLevel { self.pades_level }
    #[getter]
    fn digest_algorithm(&self) -> DigestAlgorithm { self.digest_algorithm }
    #[getter]
    fn field_name(&self) -> &str { &self.field_name }
    #[getter]
    fn page(&self) -> u32 { self.page }
    #[getter]
    fn reason(&self) -> Option<&str> { self.reason.as_deref() }
    #[getter]
    fn location(&self) -> Option<&str> { self.location.as_deref() }
    #[getter]
    fn contact_info(&self) -> Option<&str> { self.contact_info.as_deref() }
    #[getter]
    fn content_size(&self) -> usize { self.content_size }
    #[getter]
    fn tsa_url(&self) -> Option<&str> { self.tsa_url.as_deref() }
    #[getter]
    fn certify(&self) -> bool { self.certify }
    #[getter]
    fn signing_time_placement(&self) -> SigningTimePlacement { self.signing_time_placement }

    fn __repr__(&self) -> String {
        format!(
            "SigningOptions(sub_filter={:?}, level={:?}, digest={:?})",
            format!("{:?}", self.sub_filter),
            format!("{:?}", self.pades_level),
            format!("{:?}", self.digest_algorithm),
        )
    }
}

impl SigningOptions {
    /// Convert to the Rust SigningOptions type.
    pub(crate) fn to_rust(&self) -> RustSigningOptions {
        let opts = RustSigningOptions {
            sub_filter: self.sub_filter.into(),
            pades_level: self.pades_level.into(),
            digest_algorithm: self.digest_algorithm.into(),
            field_name: self.field_name.clone(),
            page: self.page,
            reason: self.reason.clone(),
            location: self.location.clone(),
            contact_info: self.contact_info.clone(),
            content_size: self.content_size,
            certify: self.certify,
            algorithm_registry: self.algorithm_registry.as_ref().map(|r| r.inner.clone()),
            cms_signing_time: None,
            signing_time_placement: self.signing_time_placement.into(),
            tsa_url: self.tsa_url.clone(),
            visible_signature: None,
        };
        opts
    }
}

/// PDF document signer.
///
/// Example::
///
///     signer = SoftwareSigner.from_pkcs12_file("identity.p12", "password")
///     options = SigningOptions(reason="Approved")
///     pdf_signer = PdfSigner(options)
///     signed_pdf = pdf_signer.sign(pdf_bytes, signer)
#[pyclass(skip_from_py_object)]
pub struct PdfSigner {
    options: SigningOptions,
}

#[pymethods]
impl PdfSigner {
    /// Create a new PDF signer with the given options.
    #[new]
    #[pyo3(signature = (options=None))]
    fn new(options: Option<&SigningOptions>) -> Self {
        Self {
            options: options.cloned().unwrap_or_else(|| {
                SigningOptions::new(
                    SubFilter::Pades,
                    PadesLevel::BB,
                    DigestAlgorithm::Sha256,
                    None, 0, None, None, None,
                    8192, None, false, None,
                    SigningTimePlacement::Signed,
                )
            }),
        }
    }

    /// Sign a PDF document.
    ///
    /// Args:
    ///     pdf_data: The PDF file contents as bytes.
    ///     signer: A SoftwareSigner to sign with.
    ///
    /// Returns:
    ///     The signed PDF as bytes.
    ///
    /// Raises:
    ///     ValueError: If signing fails.
    fn sign(&self, py: Python<'_>, pdf_data: Vec<u8>, signer: &SoftwareSigner) -> PyResult<Vec<u8>> {
        let rust_options = self.options.to_rust();
        let signer_ref = signer.inner.clone();

        py.detach(|| {
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| PyValueError::new_err(format!("Failed to create runtime: {e}")))?;

            rt.block_on(async {
                let rust_signer = RustPdfSigner::new().options(rust_options);
                rust_signer.sign(&pdf_data, signer_ref.as_ref())
                    .await
                    .map_err(|e| PyValueError::new_err(format!("{e}")))
            })
        })
    }

    fn __repr__(&self) -> String {
        format!("PdfSigner({})", self.options.__repr__())
    }
}
