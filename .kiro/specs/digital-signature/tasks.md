# Implementation Tasks

## Completed

- [x] Core signature handler (`CPP/7zip/Crypto/7zSignature.cpp/h`)
  - [x] macOS Security.framework implementation
  - [x] Windows CryptoAPI implementation
  - [x] Linux OpenSSL implementation
  - [x] Stub for unsupported platforms

- [x] Property ID definitions (`CPP/7zip/PropID.h`)
  - [x] kpidArchSignature, kpidFileSignature, kpidCertificateStore
  - [x] kpidSignerName, kpidSignatureStatus
  - [x] kpidSignerIssuer, kpidTimestampAuthority, kpidTimestampTime

- [x] Operation results (`CPP/7zip/Archive/IArchive.h`)
  - [x] kSignatureFailed, kUntrustedCert, kExpiredCert
  - [x] kSignatureRemoved (update notify)

- [x] VARTYPE mappings (`CPP/7zip/Common/PropId.cpp`)

- [x] Build integration (`CPP/7zip/7zip_gcc.mak`)
  - [x] Platform-specific library linking

- [x] Documentation
  - [x] PULL_REQUEST.md
  - [x] 7ZIP-CRYPTO.md

## Pending / Issues Found

### High Priority

- [x] **Type mismatch**: `kpidSignatureStatus` mapped to `VT_BSTR` but docs say `VT_I4`
  - Location: `CPP/7zip/Common/PropId.cpp`
  - Fix: Change VARTYPE to `VT_I4`

- [x] **Build output not gitignored**: `CPP/7zip/Bundles/Alone2/_o/` tracked
  - Location: `.gitignore`
  - Fix: Add `*/_o/` pattern

### Medium Priority

- [x] **Warning suppression undocumented**: `-Wno-switch-default` added
  - Location: Build makefiles
  - Fix: Add comment explaining why

- [x] **Large whitespace changes**: Mixed with functional changes
  - Recommendation: Consider separating in future PRs

### Low Priority / Future Work

- [ ] Integration tests with real certificates
- [ ] GUI integration (Windows File Manager)
- [x] Per-file signatures (implemented in 7zIn/7zOut/7zUpdate/7zExtract)
- [ ] HSM/PKCS#11 support

## Verification Checklist

- [x] Cross-platform build (macOS ARM64 verified)
- [x] Memory management (CFRelease, CertFreeCertificateContext, X509_free)
- [x] Error handling for crypto operations
- [x] fread() return value checking
- [x] Security constant for minimum key size (2048 bits)
- [x] Documentation comments in header files
- [ ] Integration tests with real certificates
