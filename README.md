# pyunderskrift

Python bindings for the [underskrift](https://crates.io/crates/underskrift) PDF signing and verification library.

Built with [PyO3](https://pyo3.rs/) and [maturin](https://www.maturin.rs/).

## Features

- **PDF signing** with PKCS#12 software signers (PAdES and PKCS#7 sub-filters)
- **Signature verification** with configurable trust stores and policies
- **Three-phase remote signing** for HSM / cloud signing workflows
- **Signature extraction** without verification
- **Trust store management** for signature, timestamp, and SVT certificate authorities
- **Algorithm registry** to control permitted cryptographic algorithms
- **Policy evaluation** with basic and PKIX-based signature validation policies
- GIL released during all signing, verification, and extraction operations

## Installation

```
python3 -m pip install pyunderskrift
```

Requires Python >= 3.10.

## Quick start

### Sign a PDF

```python
from pyunderskrift import PdfSigner, SoftwareSigner, SigningOptions, SubFilter

signer = SoftwareSigner.from_pkcs12_file("signer.p12", "password")
options = SigningOptions(
    sub_filter=SubFilter.Pades,
    field_name="Signature1",
    reason="Approved",
    location="Stockholm",
)

pdf_data = open("document.pdf", "rb").read()
pdf_signer = PdfSigner(options)
signed_pdf = pdf_signer.sign(pdf_data, signer)

with open("signed.pdf", "wb") as f:
    f.write(signed_pdf)
```

### Verify signatures

```python
from pyunderskrift import (
    SignatureVerifier,
    TrustStore,
    TrustStoreSet,
    SignatureStatus,
)

# Build trust stores
sig_store = TrustStore.from_pem_directory("./trust/sig")
tsa_store = TrustStore.from_pem_directory("./trust/tsa")

stores = TrustStoreSet()
stores.set_sig_store(sig_store)
stores.set_tsa_store(tsa_store)

# Verify
verifier = SignatureVerifier(stores)
pdf_data = open("signed.pdf", "rb").read()
report = verifier.verify_pdf(pdf_data)

for sig in report.signatures:
    print(f"{sig.field_name}: {sig.status} - {sig.summary}")

print(f"All valid: {report.all_valid()}")
print(f"Document modified: {report.document_modified}")
```

### Extract signatures (no verification)

```python
from pyunderskrift import extract_signatures

pdf_data = open("signed.pdf", "rb").read()
for sig in extract_signatures(pdf_data):
    print(f"  Field: {sig.field_name}")
    print(f"  Type: {sig.signature_type.kind}")
    print(f"  Signer: {sig.signer_name}")
    print(f"  Time: {sig.signing_time}")
```

### Three-phase remote signing

```python
from pyunderskrift import (
    RemoteSignerInfo,
    RemoteSigningOptions,
    DigestAlgorithm,
    SignatureAlgorithm,
    SubFilter,
    prepare_signature,
    finalize_signature,
)

# Phase 1: Prepare (caller provides signer certificate info)
signer_info = RemoteSignerInfo(
    certificate_der=cert_der_bytes,
    chain_der=[intermediate_der],
    digest_algorithm=DigestAlgorithm.Sha256,
    signature_algorithm=SignatureAlgorithm.RsaPkcs1v15,
)
options = RemoteSigningOptions(sub_filter=SubFilter.Pades)

prepared = prepare_signature(pdf_data, signer_info, options)

# Phase 2: Sign the hash remotely (e.g. via HSM API)
signature_bytes = remote_hsm_sign(prepared.attrs_hash)

# Phase 3: Finalize
signed_pdf = finalize_signature(prepared, signature_bytes)
```

### Validation policies

```python
from pyunderskrift import (
    BasicPdfSignaturePolicy,
    PkixPdfSignaturePolicy,
    SignatureVerifier,
    TrustStoreSet,
    PolicyConclusion,
)

# Basic policy: integrity + crypto + trust + no modifications
basic = BasicPdfSignaturePolicy(require_no_modifications=True)

# PKIX policy: adds revocation checks, grace periods, timestamp validation
pkix = PkixPdfSignaturePolicy(
    grace_period_secs=86400,
    require_revocation_check=True,
    require_no_modifications=True,
    use_timestamp_time=True,
)

stores = TrustStoreSet()
# ... configure stores ...

verifier = SignatureVerifier(stores)
verifier.set_pkix_policy(pkix)

report = verifier.verify_pdf(pdf_data)
for sig in report.signatures:
    if sig.policy_result is not None:
        if sig.policy_result.conclusion == PolicyConclusion.Passed:
            print(f"{sig.field_name}: policy PASSED")
        else:
            print(f"{sig.field_name}: {sig.policy_result.message}")
            for check in sig.policy_result.checks:
                if not check.passed:
                    print(f"  FAIL: {check.check_name} - {check.message}")
```

## API overview

The full API is documented in the [type stub](pyunderskrift.pyi). Key types:

### Enums

`SignatureStatus`, `DetectedPadesLevel`, `PadesLevel`, `SubFilter`,
`StoreKind`, `PolicyConclusion`, `DigestAlgorithm`, `SignatureAlgorithm`,
`SigningTimePlacement`, `RevocationSource`, `RevocationReason`

### Struct-based enums

`CryptoValidity`, `CertValidity`, `SignatureType`, `ValidationStatus` --
each has a `.kind` string property and optional variant-specific properties.

### Trust

`TrustStore`, `TrustStoreSet`

### Verification

`SignatureVerifier`, `VerificationReport`, `SignatureVerificationResult`

### Policy

`BasicPdfSignaturePolicy`, `PkixPdfSignaturePolicy`, `PolicyResult`,
`PolicyCheckResult`

### Signing

`PdfSigner`, `SigningOptions`, `SoftwareSigner`, `AlgorithmRegistry`

### Extraction

`ExtractedSignature`, `extract_signatures()`

### Remote signing

`RemoteSignerInfo`, `RemoteSigningOptions`, `PreparedSignature`,
`prepare_signature()`, `finalize_signature()`

## Building from source

Requires Rust (stable) and Python >= 3.10.

```bash
git clone https://github.com/kushaldas/pyunderskrift.git
cd pyunderskrift
uv venv
source .venv/bin/activate
uv pip install maturin pytest
maturin develop
pytest tests/ -vvv
```

To generate test fixtures (requires OpenSSL):

```bash
cd tests/fixtures
bash ../../gen-test-fixtures.sh
```

## License

BSD-2-Clause
