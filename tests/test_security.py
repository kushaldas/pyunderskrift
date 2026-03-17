#!/usr/bin/env python3
"""Security tests for pyunderskrift — validates input handling, error paths, and
boundary conditions using the actual Python API.

Run with:  python -m pytest tests/test_security.py -v
"""

import struct
import pytest
import pyunderskrift
from pyunderskrift import (
    inspect_pdf,
    inspect_signatures,
    extract_cms_by_object,
    extract_signatures,
    SignatureVerifier,
    TrustStore,
    TrustStoreSet,
)


# ── Input validation tests ──────────────────────────────────────────────────


class TestInputValidation:
    """Verify that malformed / adversarial inputs are rejected early."""

    def test_empty_input_inspect_pdf(self):
        with pytest.raises(ValueError, match="empty"):
            inspect_pdf(b"")

    def test_empty_input_inspect_signatures(self):
        with pytest.raises(ValueError, match="empty"):
            inspect_signatures(b"")

    def test_empty_input_extract_cms(self):
        with pytest.raises(ValueError, match="empty"):
            extract_cms_by_object(b"", 1)

    def test_empty_input_extract_signatures(self):
        with pytest.raises(ValueError, match="empty"):
            extract_signatures(b"")

    def test_non_pdf_inspect(self):
        with pytest.raises(ValueError, match="PDF header"):
            inspect_pdf(b"This is not a PDF file at all")

    def test_non_pdf_inspect_signatures(self):
        with pytest.raises(ValueError, match="PDF header"):
            inspect_signatures(b"NOT-A-PDF")

    def test_non_pdf_extract_cms(self):
        with pytest.raises(ValueError, match="PDF header"):
            extract_cms_by_object(b"<html>hello</html>", 1)

    def test_non_pdf_extract_signatures(self):
        with pytest.raises(ValueError, match="PDF header"):
            extract_signatures(b"just some bytes")

    def test_non_pdf_verify(self):
        """Verify that verify_pdf rejects non-PDF input."""
        store = TrustStore()
        tss = TrustStoreSet()
        tss.set_sig_store(store)
        verifier = SignatureVerifier(tss)
        with pytest.raises(ValueError, match="PDF header"):
            verifier.verify_pdf(b"not a pdf")

    def test_empty_verify(self):
        """Verify that verify_pdf rejects empty input."""
        store = TrustStore()
        tss = TrustStoreSet()
        tss.set_sig_store(store)
        verifier = SignatureVerifier(tss)
        with pytest.raises(ValueError, match="empty"):
            verifier.verify_pdf(b"")

    def test_truncated_pdf_header(self):
        """A file that starts with %PDF- but is otherwise empty."""
        with pytest.raises(ValueError):
            inspect_pdf(b"%PDF-1.7")

    def test_invalid_obj_num_extract_cms(self):
        """Request CMS from an object number that doesn't exist."""
        # Minimal valid-ish PDF header (will parse but has no objects)
        minimal = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Root 1 0 R /Size 2 >>\nstartxref\n58\n%%EOF"
        with pytest.raises(ValueError):
            extract_cms_by_object(minimal, 9999)


# ── Crafted PDF attack tests ────────────────────────────────────────────────


def _make_minimal_pdf() -> bytes:
    """Create a minimal valid PDF with no signatures.

    Builds the PDF carefully so xref offsets are correct.
    """
    body = (
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
    )
    header = b"%PDF-1.4\n"
    # Calculate offsets from start of file
    obj1_offset = len(header)
    obj2_offset = obj1_offset + len(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    )
    obj3_offset = obj2_offset + len(
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    )
    xref_offset = len(header) + len(body)

    xref = (
        b"xref\n"
        b"0 4\n"
        b"0000000000 65535 f \n"
        + f"{obj1_offset:010d} 00000 n \n".encode()
        + f"{obj2_offset:010d} 00000 n \n".encode()
        + f"{obj3_offset:010d} 00000 n \n".encode()
    )
    trailer = (
        b"trailer\n<< /Root 1 0 R /Size 4 >>\n"
        b"startxref\n" + f"{xref_offset}\n".encode() + b"%%EOF"
    )
    return header + body + xref + trailer


class TestCraftedPdfs:
    """Test behaviour with crafted/adversarial PDFs."""

    def test_pdf_no_signatures(self):
        """A valid PDF with no signatures should return an empty result."""
        pdf = _make_minimal_pdf()
        result = inspect_signatures(pdf)
        assert result.has_signatures is False
        assert result.num_signatures == 0

    def test_pdf_no_signatures_verify(self):
        """Verifying a PDF with no signatures should raise ValueError or return empty."""
        pdf = _make_minimal_pdf()
        store = TrustStore()
        tss = TrustStoreSet()
        tss.set_sig_store(store)
        verifier = SignatureVerifier(tss)
        try:
            report = verifier.verify_pdf(pdf)
            assert len(report.signatures) == 0
        except ValueError as e:
            # Also acceptable — "no signatures found" is a valid response
            assert "no signatures" in str(e).lower()

    def test_pdf_with_null_bytes_in_body(self):
        """PDF with null bytes after header — should parse or fail gracefully."""
        pdf = b"%PDF-1.4\n" + b"\x00" * 1024
        # Should either parse (returning empty) or raise ValueError, not panic
        try:
            result = inspect_signatures(pdf)
            # If it parses, it should have no signatures
            assert result.num_signatures == 0
        except ValueError:
            pass  # Expected — corrupt PDF

    def test_pdf_with_huge_object_number(self):
        """Requesting CMS from u32::MAX object should not cause issues."""
        pdf = _make_minimal_pdf()
        with pytest.raises(ValueError):
            extract_cms_by_object(pdf, 0xFFFFFFFF)

    def test_pdf_incremental_save_no_sig(self):
        """A PDF with a fake incremental save (extra %%EOF) but no signatures.
        Should either parse correctly or raise ValueError, not panic."""
        base = _make_minimal_pdf()
        # Append a fake incremental update (offsets will be wrong, but that's
        # part of the test — the library should handle it gracefully)
        incremental = base + b"\n%% incremental\n%%EOF\n"
        try:
            result = inspect_signatures(incremental)
            # If it parses, it should still have no signatures
            assert result.num_signatures == 0
        except ValueError:
            pass  # Also acceptable — corrupt incremental update


# ── Type safety tests ───────────────────────────────────────────────────────


class TestTypeSafety:
    """Verify that wrong types are rejected at the Python boundary."""

    def test_inspect_pdf_wrong_type(self):
        with pytest.raises(TypeError):
            inspect_pdf("not bytes")  # type: ignore

    def test_inspect_pdf_none(self):
        with pytest.raises(TypeError):
            inspect_pdf(None)  # type: ignore

    def test_extract_cms_string_obj_num(self):
        with pytest.raises(TypeError):
            extract_cms_by_object(b"%PDF-1.4\n", "one")  # type: ignore

    def test_extract_cms_negative_obj_num(self):
        """Negative obj_num should be rejected (u32 overflow)."""
        with pytest.raises((OverflowError, ValueError, TypeError)):
            extract_cms_by_object(b"%PDF-1.4\n", -1)
