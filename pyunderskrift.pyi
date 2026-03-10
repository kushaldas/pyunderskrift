"""Type stubs for pyunderskrift — Python bindings for the underskrift PDF signing/verification library."""

from __future__ import annotations

from typing import Optional

# ── Enums ─────────────────────────────────────────────────────────────────────
#
# PyO3 ``eq_int`` enums support equality comparison with ``int`` but are
# not Python ``IntEnum`` subclasses.  Each variant is a class attribute
# whose value is the corresponding integer.

class SignatureStatus:
    Valid: SignatureStatus
    ValidButUntrusted: SignatureStatus
    Invalid: SignatureStatus
    Indeterminate: SignatureStatus

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class DetectedPadesLevel:
    BB: DetectedPadesLevel
    BT: DetectedPadesLevel
    BLT: DetectedPadesLevel
    BLTA: DetectedPadesLevel
    NotPades: DetectedPadesLevel
    Unknown: DetectedPadesLevel

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class PadesLevel:
    BB: PadesLevel
    BT: PadesLevel
    BLT: PadesLevel
    BLTA: PadesLevel

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class SubFilter:
    Pades: SubFilter
    Pkcs7: SubFilter

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class StoreKind:
    Signature: StoreKind
    Timestamp: StoreKind
    Svt: StoreKind

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class PolicyConclusion:
    Passed: PolicyConclusion
    Failed: PolicyConclusion
    Indeterminate: PolicyConclusion

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class DigestAlgorithm:
    Sha256: DigestAlgorithm
    Sha384: DigestAlgorithm
    Sha512: DigestAlgorithm
    Sha3_256: DigestAlgorithm
    Sha3_384: DigestAlgorithm
    Sha3_512: DigestAlgorithm

    def name(self) -> str:
        """Return the algorithm name (e.g. ``'SHA-256'``)."""
        ...

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class SignatureAlgorithm:
    RsaPkcs1v15: SignatureAlgorithm
    RsaPss: SignatureAlgorithm
    EcdsaP256: SignatureAlgorithm
    EcdsaP384: SignatureAlgorithm
    Ed25519: SignatureAlgorithm

    def name(self) -> str:
        """Return the algorithm name (e.g. ``'RSA-PKCS1-v1.5'``)."""
        ...

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class SigningTimePlacement:
    Signed: SigningTimePlacement
    Unsigned: SigningTimePlacement
    Both: SigningTimePlacement

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class RevocationSource:
    Crl: RevocationSource
    Ocsp: RevocationSource

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class RevocationReason:
    Unspecified: RevocationReason
    KeyCompromise: RevocationReason
    CaCompromise: RevocationReason
    AffiliationChanged: RevocationReason
    Superseded: RevocationReason
    CessationOfOperation: RevocationReason
    CertificateHold: RevocationReason
    RemoveFromCrl: RevocationReason
    PrivilegeWithdrawn: RevocationReason
    AaCompromise: RevocationReason

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

# ── Struct-based enum wrappers ────────────────────────────────────────────────

class CryptoValidity:
    """Cryptographic signature validity result.

    The ``kind`` property is one of ``'valid'``, ``'invalid'``, or
    ``'unknown_algorithm'``.
    """

    kind: str
    message: Optional[str]

class CertValidity:
    """Certificate validation result.

    The ``kind`` property is one of ``'valid'``, ``'expired'``,
    ``'not_yet_valid'``, ``'revoked'``, ``'chain_incomplete'``,
    ``'untrusted_root'``, or ``'validation_error'``.
    """

    kind: str
    message: Optional[str]

class SignatureType:
    """Detected signature type.

    The ``kind`` property is one of ``'pades'``, ``'pkcs7_detached'``,
    ``'pkcs7_sha1'``, ``'doc_timestamp'``, or ``'unknown'``.
    """

    kind: str
    value: Optional[str]

class ValidationStatus:
    """Revocation / validation status for a certificate.

    The ``kind`` property is one of ``'valid'``, ``'revoked'``,
    ``'invalid'``, or ``'unknown'``.
    """

    kind: str
    source: Optional[str]
    """``'CRL'`` or ``'OCSP'`` when available."""
    checked_at: Optional[str]
    """ISO 8601 timestamp of the check, for ``'valid'``."""
    reason: Optional[str]
    """Human-readable revocation reason, for ``'revoked'``."""
    reason_code: Optional[int]
    """Numeric revocation reason code, for ``'revoked'``."""
    revocation_time: Optional[str]
    """ISO 8601 timestamp of revocation, for ``'revoked'``."""
    message: Optional[str]
    """Error or explanation, for ``'invalid'`` / ``'unknown'``."""

# ── Trust stores ──────────────────────────────────────────────────────────────

class TrustStore:
    """A collection of trusted CA certificates (trust anchors)."""

    def __init__(self, label: Optional[str] = None) -> None: ...
    @staticmethod
    def from_pem_file(path: str) -> TrustStore:
        """Load trust anchors from a PEM file (may contain multiple certificates)."""
        ...

    @staticmethod
    def from_pem_directory(path: str) -> TrustStore:
        """Load trust anchors from all PEM/CRT/CER files in a directory."""
        ...

    def add_der_certificate(self, der: bytes) -> None:
        """Add a trust anchor from DER-encoded bytes."""
        ...

    def add_pem_data(self, pem_data: bytes) -> None:
        """Add trust anchors from PEM-encoded data (may contain multiple certs)."""
        ...

    def contains_der(self, cert_der: bytes) -> bool:
        """Check whether a certificate (DER) is directly in this store."""
        ...

    def is_empty(self) -> bool:
        """Whether the store contains no trust anchors."""
        ...

    def certificates_der(self) -> list[bytes]:
        """Return all trust anchor certificates as DER-encoded bytes."""
        ...

    @property
    def label(self) -> Optional[str]:
        """Diagnostic label for this store, if set."""
        ...

    def __len__(self) -> int: ...
    def __repr__(self) -> str: ...

class TrustStoreSet:
    """Container for up to three trust stores: signature, timestamp, and SVT."""

    def __init__(self) -> None: ...
    def set_sig_store(self, store: TrustStore) -> None:
        """Set the signature verification trust store."""
        ...

    def set_tsa_store(self, store: TrustStore) -> None:
        """Set the timestamp authority trust store."""
        ...

    def set_svt_store(self, store: TrustStore) -> None:
        """Set the SVT issuer trust store."""
        ...

    def get(self, kind: StoreKind) -> Optional[TrustStore]:
        """Retrieve a store by kind, or ``None`` if not set."""
        ...

    def has_any(self) -> bool:
        """Whether at least one store has been set."""
        ...

    def __repr__(self) -> str: ...

# ── Verification ──────────────────────────────────────────────────────────────

class SignatureVerifier:
    """Verifier for PDF digital signatures."""

    def __init__(
        self,
        trust_stores: TrustStoreSet,
        allow_online: bool = False,
    ) -> None: ...
    def set_allow_online(self, allow: bool) -> None:
        """Set whether online validation (OCSP/CRL fetching) is allowed."""
        ...

    def set_basic_policy(self, policy: BasicPdfSignaturePolicy) -> None:
        """Set a basic PDF signature validation policy."""
        ...

    def set_pkix_policy(self, policy: PkixPdfSignaturePolicy) -> None:
        """Set a PKIX-based PDF signature validation policy."""
        ...

    def clear_policy(self) -> None:
        """Remove any previously set policy."""
        ...

    def verify_pdf(self, pdf_data: bytes) -> VerificationReport:
        """Verify all signatures in a PDF document.

        Releases the GIL during verification.

        Raises:
            ValueError: If the PDF cannot be parsed.
        """
        ...

    def __repr__(self) -> str: ...

class VerificationReport:
    """Result of verifying all signatures in a PDF."""

    signatures: list[SignatureVerificationResult]
    document_modified: bool
    valid_count: int
    invalid_count: int
    policy_passed_count: int
    policy_failed_count: int
    policy_indeterminate_count: int
    summary: str

    def all_valid(self) -> bool:
        """``True`` if every signature is cryptographically valid."""
        ...

    def any_valid(self) -> bool:
        """``True`` if at least one signature is cryptographically valid."""
        ...

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...
    def __len__(self) -> int: ...

class SignatureVerificationResult:
    """Detailed verification result for a single signature."""

    field_name: str
    status: SignatureStatus
    signature_type: SignatureType
    signer_name: Optional[str]
    signing_time: Optional[str]
    cms_signing_time: Optional[str]
    """CMS signing time as ISO 8601, if present."""
    timestamp_time: Optional[str]
    ess_cert_id_match: Optional[bool]
    validation_time_used: Optional[str]
    """ISO 8601 timestamp used for validation."""
    integrity_ok: bool
    covers_whole_document: bool
    integrity_issues: list[str]
    cryptographic_validity: CryptoValidity
    digest_matches: bool
    certificate_validity: CertValidity
    chain_trusted: bool
    trust_anchor: Optional[str]
    revocation_status: Optional[ValidationStatus]
    per_cert_revocation: list[tuple[str, ValidationStatus]]
    pades_level: DetectedPadesLevel
    modifications_after_signing: bool
    covers_whole_document_revision: Optional[bool]
    extended_by_non_safe_updates: Optional[bool]
    policy_result: Optional[PolicyResult]
    signer_cert_der: Optional[bytes]
    chain_certs_der: list[bytes]
    signature_value_bytes: bytes
    dtbsr_hash: bytes
    signature_algorithm_oid: Optional[str]
    timestamp_token_der: Optional[bytes]
    summary: str

    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

# ── Policy ────────────────────────────────────────────────────────────────────

class PolicyCheckResult:
    """Result of a single policy check."""

    check_name: str
    passed: bool
    message: Optional[str]

    def __repr__(self) -> str: ...

class PolicyResult:
    """Aggregate result of all policy checks for a signature."""

    policy_id: str
    conclusion: PolicyConclusion
    message: Optional[str]
    checks: list[PolicyCheckResult]

    def __repr__(self) -> str: ...

class BasicPdfSignaturePolicy:
    """A basic signature validation policy.

    Checks integrity, crypto validity, chain trust, and optionally
    post-signing modifications.
    """

    require_no_modifications: bool

    def __init__(self, require_no_modifications: bool = True) -> None: ...
    def __repr__(self) -> str: ...

class PkixPdfSignaturePolicy:
    """A PKIX-based signature validation policy.

    Adds revocation checking, grace periods, and time-based validation
    on top of the basic checks.
    """

    grace_period_secs: int
    require_revocation_check: bool
    require_no_modifications: bool
    enforce_current_time_validation: bool
    use_timestamp_time: bool

    def __init__(
        self,
        grace_period_secs: int = 86400,
        require_revocation_check: bool = True,
        require_no_modifications: bool = True,
        enforce_current_time_validation: bool = False,
        use_timestamp_time: bool = True,
    ) -> None: ...
    def __repr__(self) -> str: ...

# ── Cryptographic primitives ──────────────────────────────────────────────────

class SoftwareSigner:
    """A PKCS#12-based software signer."""

    @staticmethod
    def from_pkcs12_file(path: str, password: str) -> SoftwareSigner:
        """Load a signer from a PKCS#12 (.p12/.pfx) file.

        Raises:
            ValueError: If the file cannot be loaded or the password is wrong.
        """
        ...

    @staticmethod
    def from_pkcs12_data(data: bytes, password: str) -> SoftwareSigner:
        """Load a signer from PKCS#12 data in memory.

        Raises:
            ValueError: If the data cannot be parsed or the password is wrong.
        """
        ...

    def certificate_der(self) -> bytes:
        """Return the signer certificate in DER encoding."""
        ...

    def certificate_chain_der(self) -> list[bytes]:
        """Return the certificate chain (excluding signer) in DER encoding."""
        ...

    def digest_algorithm(self) -> DigestAlgorithm:
        """Return the digest algorithm used by this signer."""
        ...

    def signature_algorithm(self) -> SignatureAlgorithm:
        """Return the signature algorithm used by this signer."""
        ...

    def __repr__(self) -> str: ...

class AlgorithmRegistry:
    """Registry controlling which cryptographic algorithms are permitted."""

    def __init__(self) -> None:
        """Create an empty registry (no algorithms allowed)."""
        ...

    @staticmethod
    def allow_all() -> AlgorithmRegistry:
        """Create a registry that allows all known algorithms."""
        ...

    @staticmethod
    def standard() -> AlgorithmRegistry:
        """Create a registry with the standard set of algorithms."""
        ...

    def allow_digest(self, alg: DigestAlgorithm) -> None:
        """Allow a specific digest algorithm."""
        ...

    def allow_signature(self, alg: SignatureAlgorithm) -> None:
        """Allow a specific signature algorithm."""
        ...

    def __repr__(self) -> str: ...

# ── Signing ───────────────────────────────────────────────────────────────────

class SigningOptions:
    """Options for signing a PDF document."""

    def __init__(
        self,
        sub_filter: SubFilter = SubFilter.Pades,
        pades_level: PadesLevel = PadesLevel.BB,
        digest_algorithm: DigestAlgorithm = DigestAlgorithm.Sha256,
        field_name: Optional[str] = None,
        page: int = 0,
        reason: Optional[str] = None,
        location: Optional[str] = None,
        contact_info: Optional[str] = None,
        content_size: int = 8192,
        tsa_url: Optional[str] = None,
        certify: bool = False,
        algorithm_registry: Optional[AlgorithmRegistry] = None,
        signing_time_placement: SigningTimePlacement = SigningTimePlacement.Signed,
    ) -> None: ...
    @property
    def sub_filter(self) -> SubFilter: ...
    @property
    def pades_level(self) -> PadesLevel: ...
    @property
    def digest_algorithm(self) -> DigestAlgorithm: ...
    @property
    def field_name(self) -> str: ...
    @property
    def page(self) -> int: ...
    @property
    def reason(self) -> Optional[str]: ...
    @property
    def location(self) -> Optional[str]: ...
    @property
    def contact_info(self) -> Optional[str]: ...
    @property
    def content_size(self) -> int: ...
    @property
    def tsa_url(self) -> Optional[str]: ...
    @property
    def certify(self) -> bool: ...
    @property
    def signing_time_placement(self) -> SigningTimePlacement: ...
    def __repr__(self) -> str: ...

class PdfSigner:
    """Sign PDF documents using a software signer."""

    def __init__(self, options: Optional[SigningOptions] = None) -> None: ...
    def sign(self, pdf_data: bytes, signer: SoftwareSigner) -> bytes:
        """Sign a PDF and return the signed document as bytes.

        Releases the GIL during signing.

        Raises:
            ValueError: If signing fails.
        """
        ...

    def __repr__(self) -> str: ...

# ── Signature extraction ──────────────────────────────────────────────────────

class ExtractedSignature:
    """Metadata extracted from a PDF signature without verification."""

    field_name: str
    signature_type: SignatureType
    byte_range: list[int]
    cms_bytes: bytes
    reason: Optional[str]
    location: Optional[str]
    contact_info: Optional[str]
    signer_name: Optional[str]
    signing_time: Optional[str]

    def __repr__(self) -> str: ...

def extract_signatures(pdf_data: bytes) -> list[ExtractedSignature]:
    """Extract signature metadata from a PDF without verifying.

    Releases the GIL during extraction.

    Raises:
        ValueError: If the PDF cannot be parsed.
    """
    ...

# ── Remote (three-phase) signing ──────────────────────────────────────────────

class RemoteSignerInfo:
    """Information about the remote signer's certificate and algorithms."""

    certificate_der: bytes
    chain_der: list[bytes]
    digest_algorithm: DigestAlgorithm
    signature_algorithm: SignatureAlgorithm

    def __init__(
        self,
        certificate_der: bytes,
        chain_der: list[bytes],
        digest_algorithm: DigestAlgorithm,
        signature_algorithm: SignatureAlgorithm,
    ) -> None: ...
    def __repr__(self) -> str: ...

class RemoteSigningOptions:
    """Options for remote (three-phase) signing."""

    sub_filter: SubFilter
    digest_algorithm: DigestAlgorithm
    field_name: str
    page: int
    reason: Optional[str]
    location: Optional[str]
    contact_info: Optional[str]
    content_size: int

    def __init__(
        self,
        sub_filter: SubFilter = SubFilter.Pades,
        digest_algorithm: DigestAlgorithm = DigestAlgorithm.Sha256,
        field_name: str = "Signature1",
        page: int = 0,
        reason: Optional[str] = None,
        location: Optional[str] = None,
        contact_info: Optional[str] = None,
        content_size: int = 8192,
    ) -> None: ...
    def __repr__(self) -> str: ...

class PreparedSignature:
    """Result from phase 1 of three-phase signing.

    Contains the hash that must be signed by the remote party.
    Consumed by :func:`finalize_signature`; calling finalize a second
    time raises ``ValueError``.
    """

    @property
    def attrs_hash(self) -> bytes:
        """The hash of the signed attributes to be signed remotely."""
        ...

    def __repr__(self) -> str: ...

def prepare_signature(
    pdf_data: bytes,
    signer_info: RemoteSignerInfo,
    options: RemoteSigningOptions,
) -> PreparedSignature:
    """Phase 1: prepare a PDF for remote signing.

    Releases the GIL during preparation.

    Returns:
        A :class:`PreparedSignature` whose :attr:`~PreparedSignature.attrs_hash`
        must be signed by the remote party.

    Raises:
        ValueError: If preparation fails.
    """
    ...

def finalize_signature(
    prepared: PreparedSignature,
    signature_bytes: bytes,
) -> bytes:
    """Phase 3: finalize a signed PDF with the remote signature.

    Consumes the :class:`PreparedSignature` — calling this a second time
    raises ``ValueError``.

    Releases the GIL during finalization.

    Returns:
        The signed PDF as bytes.

    Raises:
        ValueError: If finalization fails or the signature was already consumed.
    """
    ...

# ── PDF Inspection ────────────────────────────────────────────────────────────

class ObjectKind:
    """The kind of a PDF indirect object."""

    Dictionary: ObjectKind
    Stream: ObjectKind
    Array: ObjectKind
    Name: ObjectKind
    String: ObjectKind
    Integer: ObjectKind
    Real: ObjectKind
    Boolean: ObjectKind
    Null: ObjectKind
    Reference: ObjectKind

    def as_str(self) -> str:
        """Return the kind as a string label (e.g. ``'Dictionary'``)."""
        ...

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...
    def __int__(self) -> int: ...
    def __repr__(self) -> str: ...
    def __hash__(self) -> int: ...

class PdfObjectInfo:
    """Information about a single PDF indirect object."""

    @property
    def obj_num(self) -> int:
        """Object number."""
        ...
    @property
    def gen_num(self) -> int:
        """Generation number."""
        ...
    @property
    def kind(self) -> ObjectKind:
        """The kind of object."""
        ...
    @property
    def type_name(self) -> Optional[str]:
        """The /Type entry value (e.g. ``'/Page'``), if present."""
        ...
    @property
    def subtype_name(self) -> Optional[str]:
        """The /Subtype entry value, if present."""
        ...
    @property
    def keys(self) -> list[str]:
        """Dictionary or stream dictionary keys (e.g. ``['/Type', '/MediaBox']``)."""
        ...
    @property
    def stream_length(self) -> Optional[int]:
        """For streams, the /Length value (raw, pre-decompression)."""
        ...
    @property
    def data(self) -> dict | list | str | int | float | bool | None:
        """Recursively serialized object data as native Python types."""
        ...

    def __repr__(self) -> str: ...

class PdfInspection:
    """Result of inspecting a PDF's full object tree."""

    @property
    def pdf_version(self) -> str:
        """PDF version string (e.g. ``'1.7'``)."""
        ...
    @property
    def num_pages(self) -> int:
        """Number of pages."""
        ...
    @property
    def num_objects(self) -> int:
        """Total number of indirect objects."""
        ...
    @property
    def objects(self) -> list[PdfObjectInfo]:
        """All indirect objects with their metadata and serialized data."""
        ...
    @property
    def catalog(self) -> dict | None:
        """The document catalog serialized to a dict."""
        ...

    def __repr__(self) -> str: ...

class CoverageInfo:
    """ByteRange coverage information for a signature."""

    signed_bytes: int
    file_size: int
    percentage: float
    gap_start: int
    gap_end: int
    gap_size: int

    def __repr__(self) -> str: ...

class SignatureFieldInfo:
    """Information about a single signature field."""

    field_name: Optional[str]
    obj_num: Optional[int]
    filter: Optional[str]
    sub_filter: Optional[str]
    name: Optional[str]
    reason: Optional[str]
    location: Optional[str]
    contact_info: Optional[str]
    signing_time: Optional[str]
    byte_range: Optional[list[int]]
    coverage: Optional[CoverageInfo]
    contents_length: Optional[int]
    contents_hex_preview: Optional[str]
    doc_mdp_permissions: Optional[int]
    build_app_name: Optional[str]

    def __repr__(self) -> str: ...

class VriEntry:
    """A VRI (Validation Related Information) entry from the DSS."""

    hash_key: str
    num_certs: int
    num_ocsps: int
    num_crls: int
    certs: list[bytes]
    ocsps: list[bytes]
    crls: list[bytes]

    def __repr__(self) -> str: ...

class DssInfo:
    """Document Security Store (DSS) information."""

    obj_num: Optional[int]
    num_certs: int
    num_ocsps: int
    num_crls: int
    certs: list[bytes]
    ocsps: list[bytes]
    crls: list[bytes]
    vri: list[VriEntry]

    def __repr__(self) -> str: ...

class RevisionInfo:
    """A detected PDF revision (bounded by %%EOF)."""

    index: int
    eof_offset: int
    byte_start: int
    byte_end: int

    def __repr__(self) -> str: ...

class PdfSignatureInspection:
    """Result of inspecting a PDF's signature-related structures."""

    has_signatures: bool
    num_signatures: int
    signatures: list[SignatureFieldInfo]
    dss: Optional[DssInfo]
    revisions: list[RevisionInfo]
    file_size: int

    def __repr__(self) -> str: ...

def inspect_pdf(pdf_data: bytes) -> PdfInspection:
    """Inspect all objects in a PDF.

    Parses the PDF from raw bytes, enumerates every indirect object,
    classifies it, and serializes its contents to Python-native types.

    Releases the GIL during inspection.

    Raises:
        ValueError: If the PDF cannot be parsed.
    """
    ...

def inspect_signatures(pdf_data: bytes) -> PdfSignatureInspection:
    """Inspect all signature-related data in a PDF.

    Extracts signature fields, DSS (with full DER content), and revision info.

    Releases the GIL during inspection.

    Raises:
        ValueError: If the PDF cannot be parsed.
    """
    ...

def extract_cms_by_object(pdf_data: bytes, obj_num: int) -> bytes:
    """Extract raw CMS/PKCS#7 bytes from a signature dictionary.

    Given a PDF and an object number, extracts the raw /Contents bytes
    (CMS/PKCS#7 DER data) from that signature dictionary object.

    Releases the GIL during extraction.

    Raises:
        ValueError: If the object cannot be found or has no /Contents.
    """
    ...
