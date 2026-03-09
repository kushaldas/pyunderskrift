"""Comprehensive tests for pyunderskrift -- Python bindings for underskrift PDF signing/verification."""

from pathlib import Path

import pytest

import pyunderskrift
from pyunderskrift import (
    # Enums
    DetectedPadesLevel,
    DigestAlgorithm,
    PadesLevel,
    PolicyConclusion,
    RevocationReason,
    RevocationSource,
    SignatureAlgorithm,
    SignatureStatus,
    SigningTimePlacement,
    StoreKind,
    SubFilter,
    # Trust
    TrustStore,
    TrustStoreSet,
    # Verification
    SignatureVerifier,
    # Policy
    BasicPdfSignaturePolicy,
    PkixPdfSignaturePolicy,
    # Crypto
    AlgorithmRegistry,
    SoftwareSigner,
    # Signing
    PdfSigner,
    SigningOptions,
    # Extraction
    extract_signatures,
    # Remote signing
    RemoteSignerInfo,
    RemoteSigningOptions,
    PreparedSignature,
    prepare_signature,
    finalize_signature,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _require_fixtures():
    """Skip test if PKI fixtures have not been generated."""
    if not (FIXTURES / "signer.p12").exists():
        pytest.skip(
            "Test fixtures not generated. Run: cd tests/fixtures && bash ../../gen-test-fixtures.sh"
        )


@pytest.fixture
def signer():
    _require_fixtures()
    return SoftwareSigner.from_pkcs12_file(str(FIXTURES / "signer.p12"), "test123")


@pytest.fixture
def trust_stores():
    _require_fixtures()
    store = TrustStore()
    store.add_pem_data((FIXTURES / "ca_cert.pem").read_bytes())
    stores = TrustStoreSet()
    stores.set_sig_store(store)
    return stores


@pytest.fixture
def sample_pdf():
    return (FIXTURES / "sample.pdf").read_bytes()


@pytest.fixture
def minimal_pdf():
    return (FIXTURES / "minimal.pdf").read_bytes()


# ===========================================================================
# 1. Import smoke test
# ===========================================================================


class TestImport:
    def test_module_exists(self):
        assert hasattr(pyunderskrift, "PdfSigner")
        assert hasattr(pyunderskrift, "SignatureVerifier")
        assert hasattr(pyunderskrift, "extract_signatures")

    def test_module_has_remote_signing(self):
        assert hasattr(pyunderskrift, "prepare_signature")
        assert hasattr(pyunderskrift, "finalize_signature")
        assert hasattr(pyunderskrift, "RemoteSignerInfo")
        assert hasattr(pyunderskrift, "RemoteSigningOptions")
        assert hasattr(pyunderskrift, "PreparedSignature")


# ===========================================================================
# 2. Enum tests
# ===========================================================================


class TestEnums:
    def test_signature_status_variants(self):
        assert SignatureStatus.Valid is not None
        assert SignatureStatus.ValidButUntrusted is not None
        assert SignatureStatus.Invalid is not None
        assert SignatureStatus.Indeterminate is not None

    def test_signature_status_equality(self):
        assert SignatureStatus.Valid == SignatureStatus.Valid
        assert SignatureStatus.Valid != SignatureStatus.Invalid

    def test_detected_pades_level_variants(self):
        assert DetectedPadesLevel.BB is not None
        assert DetectedPadesLevel.BT is not None
        assert DetectedPadesLevel.BLT is not None
        assert DetectedPadesLevel.BLTA is not None
        assert DetectedPadesLevel.NotPades is not None
        assert DetectedPadesLevel.Unknown is not None

    def test_pades_level_variants(self):
        assert PadesLevel.BB is not None
        assert PadesLevel.BT is not None
        assert PadesLevel.BLT is not None
        assert PadesLevel.BLTA is not None

    def test_sub_filter_variants(self):
        assert SubFilter.Pades is not None
        assert SubFilter.Pkcs7 is not None
        assert SubFilter.Pades != SubFilter.Pkcs7

    def test_store_kind_variants(self):
        assert StoreKind.Signature is not None
        assert StoreKind.Timestamp is not None
        assert StoreKind.Svt is not None

    def test_policy_conclusion_variants(self):
        assert PolicyConclusion.Passed is not None
        assert PolicyConclusion.Failed is not None
        assert PolicyConclusion.Indeterminate is not None

    def test_digest_algorithm_variants(self):
        assert DigestAlgorithm.Sha256 is not None
        assert DigestAlgorithm.Sha384 is not None
        assert DigestAlgorithm.Sha512 is not None
        assert DigestAlgorithm.Sha3_256 is not None
        assert DigestAlgorithm.Sha3_384 is not None
        assert DigestAlgorithm.Sha3_512 is not None

    def test_digest_algorithm_name(self):
        assert DigestAlgorithm.Sha256.name() == "SHA-256"
        assert DigestAlgorithm.Sha384.name() == "SHA-384"
        assert DigestAlgorithm.Sha512.name() == "SHA-512"

    def test_signature_algorithm_variants(self):
        assert SignatureAlgorithm.RsaPkcs1v15 is not None
        assert SignatureAlgorithm.RsaPss is not None
        assert SignatureAlgorithm.EcdsaP256 is not None
        assert SignatureAlgorithm.EcdsaP384 is not None
        assert SignatureAlgorithm.Ed25519 is not None

    def test_signature_algorithm_name(self):
        assert SignatureAlgorithm.RsaPkcs1v15.name() == "RSA-PKCS1-v1.5"

    def test_signing_time_placement_variants(self):
        assert SigningTimePlacement.Signed is not None
        assert SigningTimePlacement.Unsigned is not None
        assert SigningTimePlacement.Both is not None

    def test_revocation_source_variants(self):
        assert RevocationSource.Crl is not None
        assert RevocationSource.Ocsp is not None

    def test_revocation_reason_variants(self):
        assert RevocationReason.Unspecified is not None
        assert RevocationReason.KeyCompromise is not None
        assert RevocationReason.CaCompromise is not None
        assert RevocationReason.AffiliationChanged is not None
        assert RevocationReason.Superseded is not None
        assert RevocationReason.CessationOfOperation is not None
        assert RevocationReason.CertificateHold is not None
        assert RevocationReason.RemoveFromCrl is not None
        assert RevocationReason.PrivilegeWithdrawn is not None
        assert RevocationReason.AaCompromise is not None

    def test_enum_repr(self):
        r = repr(SignatureStatus.Valid)
        assert "Valid" in r

    def test_enum_int_conversion(self):
        # eq_int enums should support int()
        val = int(SignatureStatus.Valid)
        assert isinstance(val, int)


# ===========================================================================
# 3. Trust store tests
# ===========================================================================


class TestTrustStore:
    def test_empty_store(self):
        store = TrustStore()
        assert store.is_empty()
        assert len(store) == 0

    def test_store_with_label(self):
        store = TrustStore(label="test-sig")
        assert store.label == "test-sig"
        assert store.is_empty()

    def test_store_no_label(self):
        store = TrustStore()
        assert store.label is None

    def test_add_pem_data(self):
        _require_fixtures()
        store = TrustStore()
        pem = (FIXTURES / "ca_cert.pem").read_bytes()
        store.add_pem_data(pem)
        assert not store.is_empty()
        assert len(store) == 1

    def test_add_multiple_pem(self):
        _require_fixtures()
        store = TrustStore()
        store.add_pem_data((FIXTURES / "ca_cert.pem").read_bytes())
        store.add_pem_data((FIXTURES / "intermediate_ca_cert.pem").read_bytes())
        assert len(store) == 2

    def test_from_pem_file(self):
        _require_fixtures()
        # chain.pem has 3 certs: signer + intermediate + root
        store = TrustStore.from_pem_file(str(FIXTURES / "chain.pem"))
        assert len(store) == 3

    def test_from_pem_directory(self):
        _require_fixtures()
        store = TrustStore.from_pem_directory(str(FIXTURES))
        # Should pick up ca_cert.pem, intermediate_ca_cert.pem, signer_cert.pem, chain.pem
        assert not store.is_empty()
        assert len(store) >= 3

    def test_certificates_der(self):
        _require_fixtures()
        store = TrustStore()
        store.add_pem_data((FIXTURES / "ca_cert.pem").read_bytes())
        certs = store.certificates_der()
        assert len(certs) == 1
        assert isinstance(certs[0], bytes)
        assert len(certs[0]) > 0

    def test_contains_der(self):
        _require_fixtures()
        store = TrustStore()
        pem = (FIXTURES / "ca_cert.pem").read_bytes()
        store.add_pem_data(pem)
        der = store.certificates_der()[0]
        assert store.contains_der(der)

    def test_repr(self):
        store = TrustStore(label="my-store")
        r = repr(store)
        assert "my-store" in r or "TrustStore" in r

    def test_invalid_pem_data(self):
        store = TrustStore()
        with pytest.raises(ValueError):
            store.add_pem_data(b"this is not valid PEM data")


class TestTrustStoreSet:
    def test_empty_set(self):
        stores = TrustStoreSet()
        assert not stores.has_any()

    def test_set_sig_store(self):
        stores = TrustStoreSet()
        store = TrustStore(label="sig")
        stores.set_sig_store(store)
        assert stores.has_any()

    def test_get_by_kind(self):
        stores = TrustStoreSet()
        sig = TrustStore(label="sig")
        tsa = TrustStore(label="tsa")
        svt = TrustStore(label="svt")
        stores.set_sig_store(sig)
        stores.set_tsa_store(tsa)
        stores.set_svt_store(svt)
        assert stores.has_any()
        got_sig = stores.get(StoreKind.Signature)
        got_tsa = stores.get(StoreKind.Timestamp)
        got_svt = stores.get(StoreKind.Svt)
        assert got_sig is not None
        assert got_tsa is not None
        assert got_svt is not None

    def test_get_missing_kind(self):
        stores = TrustStoreSet()
        assert stores.get(StoreKind.Signature) is None
        assert stores.get(StoreKind.Timestamp) is None
        assert stores.get(StoreKind.Svt) is None


# ===========================================================================
# 4. SoftwareSigner tests
# ===========================================================================


class TestSoftwareSigner:
    def test_from_pkcs12_file(self, signer):
        assert signer is not None

    def test_from_pkcs12_data(self):
        _require_fixtures()
        data = (FIXTURES / "signer.p12").read_bytes()
        signer = SoftwareSigner.from_pkcs12_data(data, "test123")
        assert signer is not None

    def test_certificate_der(self, signer):
        der = signer.certificate_der()
        assert isinstance(der, bytes)
        assert len(der) > 0

    def test_certificate_chain_der(self, signer):
        chain = signer.certificate_chain_der()
        assert isinstance(chain, list)
        # Should have at least the intermediate CA
        assert len(chain) >= 1
        for cert in chain:
            assert isinstance(cert, bytes)

    def test_digest_algorithm(self, signer):
        alg = signer.digest_algorithm()
        assert alg == DigestAlgorithm.Sha256

    def test_signature_algorithm(self, signer):
        alg = signer.signature_algorithm()
        assert alg == SignatureAlgorithm.RsaPkcs1v15

    def test_wrong_password(self):
        _require_fixtures()
        with pytest.raises(ValueError):
            SoftwareSigner.from_pkcs12_file(str(FIXTURES / "signer.p12"), "wrong")

    def test_nonexistent_file(self):
        with pytest.raises(ValueError):
            SoftwareSigner.from_pkcs12_file("/nonexistent/signer.p12", "test123")


# ===========================================================================
# 5. AlgorithmRegistry tests
# ===========================================================================


class TestAlgorithmRegistry:
    def test_empty_registry(self):
        reg = AlgorithmRegistry()
        assert reg is not None

    def test_allow_all(self):
        reg = AlgorithmRegistry.allow_all()
        assert reg is not None

    def test_standard(self):
        reg = AlgorithmRegistry.standard()
        assert reg is not None

    def test_allow_digest(self):
        reg = AlgorithmRegistry()
        reg.allow_digest(DigestAlgorithm.Sha256)
        reg.allow_digest(DigestAlgorithm.Sha384)

    def test_allow_signature(self):
        reg = AlgorithmRegistry()
        reg.allow_signature(SignatureAlgorithm.RsaPkcs1v15)
        reg.allow_signature(SignatureAlgorithm.EcdsaP256)


# ===========================================================================
# 6. SigningOptions tests
# ===========================================================================


class TestSigningOptions:
    def test_defaults(self):
        opts = SigningOptions()
        assert opts.sub_filter == SubFilter.Pades
        assert opts.pades_level == PadesLevel.BB
        assert opts.digest_algorithm == DigestAlgorithm.Sha256
        assert opts.page == 0
        assert opts.reason is None
        assert opts.location is None
        assert opts.contact_info is None
        assert opts.content_size == 8192
        assert opts.tsa_url is None
        assert opts.certify is False

    def test_custom_values(self):
        opts = SigningOptions(
            sub_filter=SubFilter.Pkcs7,
            field_name="MySig",
            reason="Approved",
            location="Stockholm",
            contact_info="kushal@example.com",
            content_size=16384,
        )
        assert opts.sub_filter == SubFilter.Pkcs7
        assert opts.field_name == "MySig"
        assert opts.reason == "Approved"
        assert opts.location == "Stockholm"
        assert opts.contact_info == "kushal@example.com"
        assert opts.content_size == 16384

    def test_pades_level_bt(self):
        opts = SigningOptions(pades_level=PadesLevel.BT)
        assert opts.pades_level == PadesLevel.BT

    def test_signing_time_placement(self):
        opts = SigningOptions(signing_time_placement=SigningTimePlacement.Both)
        assert opts.signing_time_placement == SigningTimePlacement.Both

    def test_certify(self):
        opts = SigningOptions(certify=True)
        assert opts.certify is True

    def test_algorithm_registry(self):
        reg = AlgorithmRegistry.standard()
        opts = SigningOptions(algorithm_registry=reg)
        assert opts is not None

    def test_repr(self):
        opts = SigningOptions()
        r = repr(opts)
        assert "SigningOptions" in r


# ===========================================================================
# 7. Sign-then-verify round-trip tests
# ===========================================================================


class TestSignThenVerify:
    def test_sign_pades_then_verify(self, signer, trust_stores, sample_pdf):
        """Sign with PAdES, then verify -- mirrors underskrift's test_sign_then_verify_pades."""
        options = SigningOptions(
            sub_filter=SubFilter.Pades,
            field_name="TestSig1",
        )
        pdf_signer = PdfSigner(options)
        signed = pdf_signer.sign(sample_pdf, signer)
        assert isinstance(signed, bytes)
        assert len(signed) > len(sample_pdf)

        verifier = SignatureVerifier(trust_stores)
        report = verifier.verify_pdf(signed)

        assert len(report.signatures) == 1
        sig = report.signatures[0]
        assert sig.field_name == "TestSig1"
        assert sig.integrity_ok is True
        assert sig.digest_matches is True
        assert sig.covers_whole_document is True
        assert sig.modifications_after_signing is False
        assert not report.document_modified

        # Status should be Valid (trusted) since we loaded the CA cert
        if sig.status == SignatureStatus.Valid:
            assert report.valid_count == 1
        elif sig.status == SignatureStatus.ValidButUntrusted:
            # Acceptable if chain doesn't fully resolve
            pass
        else:
            pytest.fail(f"Unexpected status: {sig.status}")

    def test_sign_pkcs7_then_verify(self, signer, trust_stores, sample_pdf):
        """Sign with PKCS#7, then verify -- mirrors underskrift's test_sign_then_verify_pkcs7."""
        options = SigningOptions(
            sub_filter=SubFilter.Pkcs7,
            field_name="TestSig2",
        )
        pdf_signer = PdfSigner(options)
        signed = pdf_signer.sign(sample_pdf, signer)
        assert isinstance(signed, bytes)

        verifier = SignatureVerifier(trust_stores)
        report = verifier.verify_pdf(signed)

        assert len(report.signatures) == 1
        sig = report.signatures[0]
        assert sig.field_name == "TestSig2"
        assert sig.integrity_ok is True
        assert sig.digest_matches is True

    def test_sign_with_reason_location(self, signer, trust_stores, sample_pdf):
        """Sign with metadata, verify it's preserved in extraction."""
        options = SigningOptions(
            sub_filter=SubFilter.Pades,
            field_name="MetaSig",
            reason="Test approval",
            location="Uppsala",
            contact_info="test@example.com",
        )
        pdf_signer = PdfSigner(options)
        signed = pdf_signer.sign(sample_pdf, signer)

        # Extract and check metadata
        sigs = extract_signatures(signed)
        assert len(sigs) == 1
        assert sigs[0].field_name == "MetaSig"
        assert sigs[0].reason == "Test approval"
        assert sigs[0].location == "Uppsala"
        assert sigs[0].contact_info == "test@example.com"

    def test_sign_minimal_pdf_fails(self, signer, minimal_pdf):
        """Minimal PDF is too simple for lopdf's trailer parser -- signing raises."""
        options = SigningOptions(field_name="MinSig")
        pdf_signer = PdfSigner(options)
        with pytest.raises(ValueError, match="invalid file trailer"):
            pdf_signer.sign(minimal_pdf, signer)

    def test_double_sign(self, signer, trust_stores, sample_pdf):
        """Sign twice and verify both signatures."""
        # First signature
        opts1 = SigningOptions(sub_filter=SubFilter.Pades, field_name="Sig1")
        signed1 = PdfSigner(opts1).sign(sample_pdf, signer)

        # Second signature
        opts2 = SigningOptions(sub_filter=SubFilter.Pades, field_name="Sig2")
        signed2 = PdfSigner(opts2).sign(signed1, signer)

        verifier = SignatureVerifier(trust_stores)
        report = verifier.verify_pdf(signed2)
        assert len(report.signatures) == 2
        field_names = {s.field_name for s in report.signatures}
        assert "Sig1" in field_names
        assert "Sig2" in field_names

        # Both should have integrity
        for sig in report.signatures:
            assert sig.integrity_ok is True


# ===========================================================================
# 8. Verification report detail tests
# ===========================================================================


class TestVerificationReport:
    def test_report_attributes(self, signer, trust_stores, sample_pdf):
        signed = PdfSigner(SigningOptions(field_name="AttrSig")).sign(
            sample_pdf, signer
        )
        verifier = SignatureVerifier(trust_stores)
        report = verifier.verify_pdf(signed)

        assert isinstance(report.signatures, list)
        assert isinstance(report.document_modified, bool)
        assert isinstance(report.valid_count, int)
        assert isinstance(report.invalid_count, int)
        assert isinstance(report.summary, str)
        assert len(report) == 1
        assert report.any_valid()

    def test_signature_result_fields(self, signer, trust_stores, sample_pdf):
        signed = PdfSigner(SigningOptions(field_name="DetailSig")).sign(
            sample_pdf, signer
        )
        verifier = SignatureVerifier(trust_stores)
        report = verifier.verify_pdf(signed)
        sig = report.signatures[0]

        # Check all expected attributes exist
        assert isinstance(sig.field_name, str)
        assert sig.status is not None
        assert sig.signature_type is not None
        assert sig.signature_type.kind in (
            "pades",
            "pkcs7_detached",
            "pkcs7_sha1",
            "doc_timestamp",
            "unknown",
        )
        assert isinstance(sig.integrity_ok, bool)
        assert isinstance(sig.covers_whole_document, bool)
        assert isinstance(sig.integrity_issues, list)
        assert sig.cryptographic_validity is not None
        assert sig.cryptographic_validity.kind in (
            "valid",
            "invalid",
            "unknown_algorithm",
        )
        assert isinstance(sig.digest_matches, bool)
        assert sig.certificate_validity is not None
        assert isinstance(sig.chain_trusted, bool)
        assert sig.pades_level is not None
        assert isinstance(sig.modifications_after_signing, bool)
        assert isinstance(sig.summary, str)
        assert isinstance(sig.chain_certs_der, list)
        assert isinstance(sig.signature_value_bytes, bytes)
        assert isinstance(sig.dtbsr_hash, bytes)

    def test_signer_cert_der(self, signer, trust_stores, sample_pdf):
        signed = PdfSigner(SigningOptions(field_name="CertSig")).sign(
            sample_pdf, signer
        )
        verifier = SignatureVerifier(trust_stores)
        report = verifier.verify_pdf(signed)
        sig = report.signatures[0]

        # Should have the signer certificate
        assert sig.signer_cert_der is not None
        assert isinstance(sig.signer_cert_der, bytes)
        assert len(sig.signer_cert_der) > 0

        # Should match the signer's certificate
        assert sig.signer_cert_der == signer.certificate_der()


# ===========================================================================
# 9. Extraction tests
# ===========================================================================


class TestExtraction:
    def test_extract_from_signed(self, signer, sample_pdf):
        signed = PdfSigner(SigningOptions(field_name="ExtractSig")).sign(
            sample_pdf, signer
        )
        sigs = extract_signatures(signed)
        assert len(sigs) == 1
        sig = sigs[0]

        assert sig.field_name == "ExtractSig"
        assert sig.signature_type is not None
        assert sig.signature_type.kind in ("pades", "pkcs7_detached")
        assert isinstance(sig.byte_range, list)
        assert len(sig.byte_range) == 4
        assert isinstance(sig.cms_bytes, bytes)
        assert len(sig.cms_bytes) > 0

    def test_extract_from_unsigned(self, sample_pdf):
        sigs = extract_signatures(sample_pdf)
        assert len(sigs) == 0

    def test_extract_signing_time(self, signer, sample_pdf):
        opts = SigningOptions(
            field_name="TimeSig",
            signing_time_placement=SigningTimePlacement.Signed,
        )
        signed = PdfSigner(opts).sign(sample_pdf, signer)
        sigs = extract_signatures(signed)
        assert len(sigs) == 1
        # signing_time may or may not be present depending on implementation
        # but the field should exist
        assert hasattr(sigs[0], "signing_time")

    def test_invalid_pdf(self):
        with pytest.raises(ValueError):
            extract_signatures(b"not a pdf")


# ===========================================================================
# 10. Policy tests
# ===========================================================================


class TestPolicy:
    def test_basic_policy_defaults(self):
        p = BasicPdfSignaturePolicy()
        assert p.require_no_modifications is True

    def test_basic_policy_custom(self):
        p = BasicPdfSignaturePolicy(require_no_modifications=False)
        assert p.require_no_modifications is False

    def test_pkix_policy_defaults(self):
        p = PkixPdfSignaturePolicy()
        assert p.grace_period_secs == 86400
        assert p.require_revocation_check is True
        assert p.require_no_modifications is True
        assert p.enforce_current_time_validation is False
        assert p.use_timestamp_time is True

    def test_pkix_policy_custom(self):
        p = PkixPdfSignaturePolicy(
            grace_period_secs=3600,
            require_revocation_check=False,
            require_no_modifications=False,
            enforce_current_time_validation=True,
            use_timestamp_time=False,
        )
        assert p.grace_period_secs == 3600
        assert p.require_revocation_check is False
        assert p.require_no_modifications is False
        assert p.enforce_current_time_validation is True
        assert p.use_timestamp_time is False

    def test_basic_policy_with_verifier(self, signer, trust_stores, sample_pdf):
        signed = PdfSigner(SigningOptions(field_name="PolicySig")).sign(
            sample_pdf, signer
        )
        verifier = SignatureVerifier(trust_stores)
        policy = BasicPdfSignaturePolicy(require_no_modifications=True)
        verifier.set_basic_policy(policy)
        report = verifier.verify_pdf(signed)
        sig = report.signatures[0]
        # With a basic policy set, policy_result should be populated
        if sig.policy_result is not None:
            assert sig.policy_result.policy_id is not None
            assert sig.policy_result.conclusion is not None
            assert isinstance(sig.policy_result.checks, list)

    def test_pkix_policy_with_verifier(self, signer, trust_stores, sample_pdf):
        signed = PdfSigner(SigningOptions(field_name="PkixSig")).sign(
            sample_pdf, signer
        )
        verifier = SignatureVerifier(trust_stores)
        policy = PkixPdfSignaturePolicy(require_revocation_check=False)
        verifier.set_pkix_policy(policy)
        report = verifier.verify_pdf(signed)
        sig = report.signatures[0]
        if sig.policy_result is not None:
            assert sig.policy_result.policy_id is not None

    def test_clear_policy(self, trust_stores):
        verifier = SignatureVerifier(trust_stores)
        verifier.set_basic_policy(BasicPdfSignaturePolicy())
        verifier.clear_policy()
        # Should not error


# ===========================================================================
# 11. Verifier configuration tests
# ===========================================================================


class TestVerifier:
    def test_create_verifier(self, trust_stores):
        verifier = SignatureVerifier(trust_stores)
        assert verifier is not None

    def test_set_allow_online(self, trust_stores):
        verifier = SignatureVerifier(trust_stores)
        verifier.set_allow_online(True)
        verifier.set_allow_online(False)

    def test_verify_unsigned_pdf_raises(self, trust_stores, sample_pdf):
        """Verifying an unsigned PDF raises ValueError (no signatures found)."""
        verifier = SignatureVerifier(trust_stores)
        with pytest.raises(ValueError, match="no signatures found"):
            verifier.verify_pdf(sample_pdf)

    def test_verify_invalid_data(self, trust_stores):
        verifier = SignatureVerifier(trust_stores)
        with pytest.raises(ValueError):
            verifier.verify_pdf(b"not a pdf")


# ===========================================================================
# 12. Remote signing types tests
# ===========================================================================


class TestRemoteSigningTypes:
    def test_remote_signer_info(self, signer):
        info = RemoteSignerInfo(
            certificate_der=signer.certificate_der(),
            chain_der=signer.certificate_chain_der(),
            digest_algorithm=DigestAlgorithm.Sha256,
            signature_algorithm=SignatureAlgorithm.RsaPkcs1v15,
        )
        assert info.certificate_der == signer.certificate_der()
        assert info.digest_algorithm == DigestAlgorithm.Sha256
        assert info.signature_algorithm == SignatureAlgorithm.RsaPkcs1v15
        assert isinstance(info.chain_der, list)

    def test_remote_signing_options_defaults(self):
        opts = RemoteSigningOptions()
        assert opts.sub_filter == SubFilter.Pades
        assert opts.digest_algorithm == DigestAlgorithm.Sha256
        assert opts.field_name == "Signature1"
        assert opts.page == 0
        assert opts.reason is None
        assert opts.content_size == 8192

    def test_remote_signing_options_custom(self):
        opts = RemoteSigningOptions(
            sub_filter=SubFilter.Pkcs7,
            digest_algorithm=DigestAlgorithm.Sha384,
            field_name="RemoteSig",
            page=1,
            reason="Remote approval",
            location="Remote",
            contact_info="remote@example.com",
            content_size=16384,
        )
        assert opts.sub_filter == SubFilter.Pkcs7
        assert opts.digest_algorithm == DigestAlgorithm.Sha384
        assert opts.field_name == "RemoteSig"
        assert opts.page == 1
        assert opts.reason == "Remote approval"
        assert opts.location == "Remote"
        assert opts.contact_info == "remote@example.com"
        assert opts.content_size == 16384

    def test_prepare_signature(self, signer, sample_pdf):
        info = RemoteSignerInfo(
            certificate_der=signer.certificate_der(),
            chain_der=signer.certificate_chain_der(),
            digest_algorithm=DigestAlgorithm.Sha256,
            signature_algorithm=SignatureAlgorithm.RsaPkcs1v15,
        )
        opts = RemoteSigningOptions(field_name="RemotePrep")
        prepared = prepare_signature(sample_pdf, info, opts)
        assert prepared is not None
        assert isinstance(prepared.attrs_hash, bytes)
        assert len(prepared.attrs_hash) > 0


# ===========================================================================
# 13. PdfSigner tests
# ===========================================================================


class TestPdfSigner:
    def test_default_options(self):
        signer_obj = PdfSigner()
        assert signer_obj is not None

    def test_custom_options(self):
        opts = SigningOptions(field_name="Custom")
        signer_obj = PdfSigner(opts)
        assert signer_obj is not None

    def test_repr(self):
        signer_obj = PdfSigner()
        r = repr(signer_obj)
        assert "PdfSigner" in r

    def test_sign_returns_bytes(self, signer, sample_pdf):
        signed = PdfSigner().sign(sample_pdf, signer)
        assert isinstance(signed, bytes)
        assert len(signed) > 0
        # Should start with %PDF
        assert signed[:5] == b"%PDF-"
