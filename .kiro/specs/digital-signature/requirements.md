# Digital Signature Verification for 7-Zip Archives

## Overview

Enterprise-grade digital signature verification for 7-Zip archives using CMS/PKCS#7 signatures with X.509 certificates. Enables cryptographic validation of archive integrity and authenticity.

## User Stories

### US-1: Archive Signing
**As a** software distributor  
**I want to** sign 7-Zip archives with my code signing certificate  
**So that** recipients can verify the archive came from me and hasn't been tampered with

**Acceptance Criteria:**
- [ ] Can sign archives using PFX/P12 certificate files
- [ ] Can sign using system keychain/certificate store (macOS/Windows)
- [ ] Can select certificate by name substring or SHA-1 thumbprint
- [ ] Can list available signing identities with `-dsc"list"`
- [ ] Signature stored as CMS detached signature in archive properties

### US-2: Archive Verification
**As a** software consumer  
**I want to** verify the digital signature of a 7-Zip archive  
**So that** I can trust the archive hasn't been modified and comes from a trusted source

**Acceptance Criteria:**
- [ ] Automatic verification on extract/test operations
- [ ] Display signer identity on successful verification
- [ ] Clear error messages for: signature failed, untrusted cert, expired cert
- [ ] Support custom trust store via `-dst{path}`
- [ ] Option to ignore signature errors via `-dsi`

### US-3: Security Warnings
**As a** security-conscious user  
**I want to** be warned about weak cryptographic practices  
**So that** I can make informed decisions about trusting signed archives

**Acceptance Criteria:**
- [ ] Warning for RSA keys < 2048 bits
- [ ] Warning for MD5/SHA-1 signature algorithms
- [ ] Warning for certificates missing code signing EKU
- [ ] Warnings don't block extraction (informational only)

### US-4: Revocation Checking
**As an** enterprise administrator  
**I want to** verify certificates haven't been revoked  
**So that** compromised certificates are rejected

**Acceptance Criteria:**
- [ ] Soft-fail revocation checking by default (allow if CRL/OCSP unavailable)
- [ ] Hard-fail mode via `-dsrh` (require successful revocation check)
- [ ] Disable revocation via `-dsr0`
- [ ] Explicit revocation (cert on CRL) always fails

### US-5: Timestamp Support
**As a** long-term archive maintainer  
**I want to** signatures with timestamps to remain valid after certificate expiry  
**So that** archives signed before cert expiration are still trusted

**Acceptance Criteria:**
- [ ] Detect RFC 3161 timestamp tokens in signatures
- [ ] Display TSA (Time Stamping Authority) name
- [ ] Expired cert + valid timestamp = signature OK
- [ ] Display timestamp date/time

### US-6: Cross-Platform Support
**As a** developer  
**I want to** sign and verify on any major platform  
**So that** I can use 7-Zip signatures in my workflow regardless of OS

**Acceptance Criteria:**
- [ ] macOS: Security.framework (CMSEncoder/CMSDecoder)
- [ ] Windows: CryptoAPI (CryptSignMessage/CryptVerifyDetachedMessageSignature)
- [ ] Linux: OpenSSL (CMS_sign/CMS_verify)
- [ ] Consistent behavior across platforms

## CLI Interface

| Switch | Description | Default |
|--------|-------------|---------|
| `-dsc{cert}` | Sign with certificate (file path or keychain selector) | - |
| `-dsk{key}` | Private key file (Linux only, optional for PFX) | - |
| `-dst{path}` | Custom trust store (CA certificates) | System store |
| `-dsrh` | Hard-fail revocation | Soft-fail |
| `-dsr0` | Disable revocation checking | Enabled |
| `-dsi` | Ignore signature errors | Error on failure |

## Technical Requirements

### New Property IDs
- `kpidArchSignature` - CMS detached signature (binary)
- `kpidFileSignature` - Per-file signature (future)
- `kpidCertificateStore` - Certificate chain (binary)
- `kpidSignerName` - Signer subject name (runtime)
- `kpidSignatureStatus` - Verification result (runtime)
- `kpidSignerIssuer` - Certificate issuer name
- `kpidTimestampAuthority` - TSA name
- `kpidTimestampTime` - Timestamp value (ISO 8601)

### New Operation Results
- `kSignatureFailed` - CMS signature verification failed
- `kUntrustedCert` - Certificate chain validation failed
- `kExpiredCert` - Certificate has expired

### Security Constants
- Minimum secure key size: 2048 bits (NIST recommendation)
- Default hash algorithm: SHA-256

## Out of Scope (Future Work)
- Full RFC 3161 timestamp validation (presence detection only)
- GUI integration (CLI only)
- Per-file signatures (archive-level only)
- HSM/PKCS#11 support

## References
- RFC 5652: Cryptographic Message Syntax (CMS)
- RFC 3161: Time-Stamp Protocol (TSP)
- NIST SP 800-131A: Transitioning Cryptographic Algorithms
