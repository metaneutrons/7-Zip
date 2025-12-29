# 7-Zip Extension for Signatures

This document outlines the research findings and proposed architecture for extending the 7-Zip format to support cryptographic signatures.

## Executive Summary

This proposal defines the architecture for extending the 7-Zip archive format to support enterprise-grade cryptographic signatures. By integrating X.509 Certificates within CMS (Cryptographic Message Syntax / PKCS#7) containers, we establish a robust mechanism for both whole-archive tamper-proofing and per-file source integrity checks. This solution enables trust chain validation while preserving backward compatibility with existing 7-Zip versions.

## 1. Architecture: Dual Signing Strategy

We will support two distinct signing modes as requested.

### A. Whole Archive Signing (Tamper-Proofing)

**Goal**: Guarantee the archive (compressed data + metadata) has not been altered.
**Behavior**: Default = Error

### Core Components

#### 1. `CPP/7zip/PropID.h`

- **Goal:** Define new Property IDs with strict data formats.
- **Changes:**
  - `kpidArchSignature` (0x25): **Binary (VT_BSTR)**. DER-encoded CMS `SignedData` (RFC 5652). Detached signature.
  - `kpidFileSignature` (0x26): **Binary (VT_BSTR)**. DER-encoded CMS `SignedData` (RFC 5652). Detached signature.
  - `kpidCertificateStore` (0x27): **Binary (VT_BSTR)**. DER-encoded CMS "Certs-Only" message (RFC 5652). (`certificates` field populated, `signerInfos` empty).
  - `kpidSignerName` (0x28): **String (VT_BSTR)**. Runtime-only. Signer's subject name derived from signature certificate.
  - `kpidSignatureStatus` (0x29): **Int32 (VT_I4)**. Runtime-only. Verification result (0=OK, values from `NOperationResult`).

#### 2. `CPP/7zip/Crypto/7zSignature.h` (NEW)

- **Goal:** Abstraction layer for Crypto operations (mbedTLS/WinCrypt).
- **Interface:**

  ```cpp
  struct CCertInfo {
    UString Subject;
    UString Issuer;
    UString Algo;     // e.g. "RSA-2048-SHA256"
    bool IsExpired;
    bool IsWeakKey;   // e.g. RSA < 2048
    bool IsWeakAlgo;  // e.g. SHA1
    UString ExpiryDate; 
  };

  class CSignatureHandler {
  public:
    // ... setters ...
    // Configuration
    HRESULT SetSignatureAlgorithm(const UString &algoName); // e.g. "SHA256"
    HRESULT GetSupportedAlgorithms(UStringVector &algos); // for Help

    // Operations
    HRESULT Sign(const Byte *data, size_t size, CByteBuffer &signature);
    HRESULT Verify(const Byte *data, size_t size, const Byte *sig, size_t sigLen,
                   NExtract::NOperationResult::EEnum &result, CCertInfo &certInfo);
  };
  ```

#### 5. `CPP/7zip/UI/Console/ExtractCallbackConsole.cpp`

- **Goal:** Report status to the user.
- **Variables:**

  ```cpp
  static const char * const kSignatureFailed = "Digital Signature Verification Failed";
  static const char * const kUntrustedCert = "Certificate Authority is not trusted";
  static const char * const kVerifiedSigner = "Signed by: ";
  static const char * const kWarnWeakKey = "WARNING: Signing Certificate uses weak key (Recommended: RSA 2048+)";
  static const char * const kWarnSha1 = "WARNING: Weak Legacy Algorithm (SHA-1)";
  ```

- **Logic:**
  - In `SetOperationResult`:
    - Perform primary checks (Valid/Trusted).
    - If `kOK`, print signer name.
    - **Health Checks**: Check `CertInfo` properties.
      - If `IsWeakKey`: Print `kWarnWeakKey`.
      - If `IsWeakAlgo`: Print `kWarnSha1`.

#### 2. `CPP/7zip/Archive/IArchive.h`

- **Goal:** Extend operation results to support crypto failures.
- **Changes:**
  - Add to `namespace NArchive::NExtract::NOperationResult`:
    - `kSignatureFailed`
    - `kUntrustedCert`

#### 3. `CPP/7zip/Archive/7z/7zOut.cpp`

- **Location:** `WriteDatabase` function.
- **Logic:**
  - After calculating the Header Hash (or Packed Streams Hash), calculate the signature.
  - Insert a new `ArchiveProperty` block with ID `0x25` (proposed `kArchiveSignature`).
  - Write the CMS blob.
  - **Optimization**: File signatures MUST reference `kCertificateStore` certificates using **Subject Key Identifier (SKI)**. Do not embed certificates in per-file signatures.

#### 4. `CPP/7zip/Archive/7z/7zIn.cpp` & `7zHandler.cpp`

- **Goal:** Read and Verify.
- **Logic:**
  - In `ReadDatabase`, parse the new property ID `0x25`.
  - Store the signature blob in `CHandler`.
  - On `Open` (or demand), calculate the hash of the relevant streams/header.
  - Verify the signature using the stored certs.
  - Store the result (`kOK`, `kSignatureFailed`, `kUntrustedCert`) and the Signer Name.

#### 5. `CPP/7zip/UI/Console/ExtractCallbackConsole.cpp`

- **Goal:** Report status to the user.
- **Variables:**

  ```cpp
  static const char * const kSignatureFailed = "Digital Signature Verification Failed";
  static const char * const kUntrustedCert = "Certificate Authority is not trusted";
  static const char * const kVerifiedSigner = "Signed by: ";
  static const char * const kWarnWeakKey = "WARNING: Signing Certificate uses weak key (Recommended: RSA 2048+)";
  static const char * const kWarnSha1 = "WARNING: Weak Legacy Algorithm (SHA-1)";
  ```

- **Logic:**
  - In `SetOperationResult`:
    - Perform primary checks (Valid/Trusted).
    - If `kOK`, print signer name.
    - **Health Checks**: Check `CertInfo` properties.
      - If `IsWeakKey`: Print `kWarnWeakKey`.
      - If `IsWeakAlgo`: Print `kWarnSha1`.

#### 6. CLI Switches (`ArchiveCommandLine.cpp`, `Main.cpp`)

- **`ArchiveCommandLine.cpp`**: Add new `kSwitchForms` (`dsc`, `dsk`, `dst`, `dsi`, `dsa`).
- **`Main.cpp`**:
  - Parse `-dsc`/`-dsk` into `CUpdateOptions` (for `a` / Add command).
  - Parse `-dst`/`-dsi` into `CExtractOptions` (for `x`/`e`/`t` commands).
  - **`-dsa {name}`**: Select signature algorithm (e.g., `-dsa sha256`).
    - If `{name}` is "help" or invalid, call `CSignatureHandler::GetSupportedAlgorithms` and print the availability list.
- Inspect the output confirming the "Signed by: ..." message appears.
- Hex editor check: Verify the `0x25` property ID exists in the header.
- **Behavior**: Default = Error on tamper. Override via `-dsi` (Digital Signature Ignore).

- **Mechanism**:
  - **Location**: A new property in `ArchiveProperties` (ID: `kArchiveSignature` / `0x25`).
  - **Content**: A **CMS (PKCS#7) Detached Signature**.
  - **What is Signed**:
    - A SHA-256 hash of the **Packed Streams** (the raw compressed data).
    - A SHA-256 hash of the **Header** (metadata), *excluding* the Signature Property itself.
- **Verification Process**:
    1. Extract the Checksum/Hash from the Archive Header.
    2. Calculate the actual Hash of the loaded streams/header.
    3. Verify the CMS Signature against the calculated Hash using the embedded Public Key.
    4. **Trust Check**: Validate the Public Key's certificate chain against the System Trust Store (or a provided CA bundle).

### B. Per-File Signing (Source Integrity)

**Goal**: Guarantee individual files have not been altered since compression.

- **Mechanism**:
  - **Certificate Store**: `kCertificateStore` (0x27) in `ArchiveProperties`. Use a **CMS "Certs-Only" message** to store the Signer's Certificate and the simplified Chain of Trust. This is the *single source of truth* for identity in the archive.
  - **Signatures**: `kFileSignature` (0x26) in `FilesInfo`.
  - **Format**: **CMS (PKCS#7) Detached Signature** (SignerInfo only).
  - **Optimization**: To avoid redundancy, individual file signatures **MUST NOT** embed certificates. They must reference the certificates in `kCertificateStore` using **Subject Key Identifier (SKI)**.
- **Verified Data**: The uncompressed data stream of the individual file.

## 2. Certificates and Formats

### Format: CMS / PKCS#7 (RFC 5652)

- **Why**: Industry standard for "signed files". Supports:
  - **Algorithm Agility**: Can switch between RSA, ECDSA, Ed25519 easily.
  - **Certificates**: Can embed the Signer's Certificate and Intermediate CAs.
  - **Attributes**: Can embed Signing Time, Countersignatures, etc.
- **Encoding**: DER (Binary) for compactness within the 7z format.

### Certificates: X.509 v3

- **Why**: Required for "Chain of Trust".
- **Trust Anchor**:
  - **Windows**: Use Microsoft CryptoAPI (`CertGetCertificateChain`) to check against the Windows Root Store.
  - **Linux/macOS**: Use OpenSSL/mbedTLS checking against `/etc/ssl/certs` or Keychain.

## 3. Technical Implementation Challenges

The 7-Zip codebase currently **only** includes AES (custom implementation) and CRC. It has **no** PKI capability.

### Recommendation: Integrate mbedTLS

To parse X.509 and verify CMS signatures without adding a massive dependency (like OpenSSL), we should link **mbedTLS** (or wolfSSL).

- **Pros**: Small static footprint, license-friendly (Apache 2.0), cross-platform.
- **Cons**: Adds a build dependency.

### Alternative: OS Native APIs (Windows & macOS)

- **Windows**: Use `wincrypt.h` (CryptoAPI). Zero external dependencies.
- **macOS**: Use **Security.framework**.
  - `CMSDecoder` for parsing/verifying detached signatures.
  - `SecTrustEvaluateWithError` for validating certificate chains against the System Keychain.
  - **Advantage**: Zero external dependencies, fully native trust integration.

**Proposal**: Use **OS Native APIs** for both **Windows** (`wincrypt`) and **macOS** (`Security.framework`) to keep the primary executables small and integrated. Use **mbedTLS** only for Linux and other Unix-like systems.

## 4. Proposed Changes

### [MODIFY] [7zHeader.h](file:///Users/fabian/Source/7-Zip/CPP/7zip/Archive/7z/7zHeader.h)

- Add IDs:
  - `kArchiveSignature = 0x25`
  - `kFileSignature = 0x26`
  - `kCertificateStore = 0x27`

### [MODIFY] [7zOut.cpp](file:///Users/fabian/Source/7-Zip/CPP/7zip/Archive/7z/7zOut.cpp)

- **Archive Signing**: calculate SHA-256 of packed streams + header. Call Signer (OS/Lib). Write CMS blob to `ArchiveProperties`.
- **File Signing**: Accept external signatures during compression or calculate them using a provided Private Key. Write to `FilesInfo`.

### [MODIFY] [7zIn.cpp](file:///Users/fabian/Source/7-Zip/CPP/7zip/Archive/7z/7zIn.cpp)

- **Read**: Parse the new Properties.
- **Verify**:
  - If `kArchiveSignature` exists, verify it immediately upon opening.
  - **Failure Mode**: If verification fails, return `S_FALSE` or throw specific error. Check for CLI flag `-dsi` (to be added to `ExtractOptions`).

## 5. Next Steps

1. **Approval**: Confirm usage of CMS/PKCS#7 and X.509.
2. **Prototype**: Create a "dummy" signer that writes a specific byte sequence to these properties to prove format capability.
3. **Crypto Integration**: Begin integrating the Signing/Verification logic.

### 6. User Interface (CLI)

To align with 7-Zip's existing switch syntax (e.g., `-p`, `-m`, `-s...`), we propose a new switch group `-ds` (Digital Signature).

#### New Switches

- **`-dsc {path}`**: **Digital Signature Certificate**. Path to the Signer's Certificate (PEM/DER) or **Identity Store** (PFX/P12).
  - Example: `7zz a archive.7z files -dsc signer.pfx` (implies Key is inside).
- **`-dsk {path}`**: **Digital Signature Key**. Path to the Signer's Private Key.
  - **Optional** if `-dsc` points to a PFX/P12 containing the private key.
- **`-dsi`**: **Digital Signature Ignore**. Ignore signature verification errors during extraction or testing. Overrides the default "tamper/error" behavior.
  - Example: `7zz x archive.7z -dsi`
- **`-dst{path}`**: **Digital Signature Trust**. (Optional) Path to a custom CA bundle/trust store. If omitted, uses System Trust Store.

#### Verification Behavior & Best Practices

To follow security best practices ("Secure by Default"):

1. **Trust Chain Validation**: MANDATORY by default. The signer's certificate MUST chain up to a Root CA in the user's System Trust Store (or the bundle provided via `-dst`).
    - **Self-Signed Certificates**: Will fail by default unless the certificate itself is passed in `-dst` or explicitly trusted by the OS.
2. **Extraction Failure**:
    - If **Hash Mismatch**: ABORT. Print "CRITICAL: Archive Content Tampered".
    - If **Untrusted Root**: ABORT. Print "ERROR: Untrusted Certificate Authority".
    - If **Expired/Revoked**: ABORT. Print "ERROR: Certificate Expired/Revoked".
3. **User Feedback**:
    - **Success**: On successful open/verification, print the Signer's Identity (Common Name / Org) to stdout.
        - `Signed by: "7-Zip Official Distribution" (Valid until: 2026-01-01)`
    - **Silence**: Verification details are suppressed if `-bb0` (quiet) is used, but Errors are always printed.

#### Command Integration

- **`a` (Add)**: If `-dsk` is present, signatures are generated and added.
- **`x` / `e` (Extract)**: Automatically verifies signatures/trust if present.
  - **Valid**: Prints signer identity and extracts.
  - **Invalid**: Prints specific error (Tamper vs Untrusted) and aborts (unless `-dsi` is used).

## Verification Plan

### Integration Verification (CLI)

Since 7-Zip relies on end-to-end integration testing, we will verify correctness using the `7z` CLI itself.

1. **Creation & Signing**:

    ```bash
    7zz a archive.7z files/ -dsc cert.pem -dsk key.pem
    ```

    *Expectation*: Archive created, header contains Property ID `0x25`.

2. **Verification (Standard)**:

    ```bash
    7zz t archive.7z
    ```

    *Expectation*: Output contains "Signed by: [Subject]" and "Everything is Ok".

3. **Tamper Detection**:
    - Modify 1 byte in `archive.7z`.
    - Run `7zz t archive.7z`
    - *Expectation*: Output contains "ERROR: Digital Signature Verification Failed".

4. **Untrusted Root**:
    - Sign with a self-signed cert not in the system store.
    - Run `7zz t archive.7z`
    - *Expectation*: Output contains "ERROR: Certificate Authority is not trusted".
    - Run `7zz t archive.7z -dst selfsigned.pem`
    - *Expectation*: Success ("Signed by...").

5. **Force Ignore (`-dsi`)**:
    - Run `7zz x tampered.7z -dsi`
    - *Expectation*: Extraction succeeds despite signature error (warning printed).

6. **Best Practice Warning**:
    - Sign with an RSA-1024 key (if possible to generate for test).
    - Run `7zz t weak.7z`
    - *Expectation*: "Everything is Ok" BUT output contains "WARNING: Signing Certificate uses weak key".
