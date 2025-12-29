# Digital Signature Design

## Architecture

### Dual Signing Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                     7z Archive                              │
├─────────────────────────────────────────────────────────────┤
│  Packed Streams (compressed data)                           │
├─────────────────────────────────────────────────────────────┤
│  Header                                                     │
│  ├── File Metadata                                          │
│  ├── kpidArchSignature ─► CMS Detached Signature            │
│  ├── kpidCertificateStore ─► Certificate Chain              │
│  └── kpidFileSignature ─► Per-file CMS Signatures (future)  │
└─────────────────────────────────────────────────────────────┘
```

### Verification Flow

```
Open Archive → Extract CMS Sig → Verify Signature
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                             │                             │
   Build Trust Chain          Check Revocation           Validate EKU
         │                             │                             │
         └─────────────────────────────┼─────────────────────────────┘
                                       │
                               Return Result + Cert Info
```

## Platform Implementations

| Platform | Crypto Library | Sign | Verify | Keychain/Store |
|----------|---------------|------|--------|----------------|
| macOS    | Security.framework | ✓ | ✓ | ✓ (Keychain) |
| Windows  | CryptoAPI | ✓ | ✓ | ✓ (Certificate Store) |
| Linux    | OpenSSL 1.1+ | ✓ | ✓ | ✗ (file-based only) |

## Key Design Decisions

### 1. Native Crypto APIs
**Decision**: Use OS-native crypto instead of bundled library (mbedTLS)  
**Rationale**: Zero external dependencies, native trust store integration, smaller binary size

### 2. Soft-Fail Revocation Default
**Decision**: Allow verification if CRL/OCSP unavailable  
**Rationale**: 
- Security should be opt-out, not opt-in
- Hard-fail would break offline/air-gapped environments
- Explicit revocation (cert on CRL) still fails hard

### 3. EKU Warning vs Error
**Decision**: Missing code signing EKU is warning, not error  
**Rationale**: Many internal/test certificates lack EKU but are still valid for signing

### 4. OID Byte Scanning for Weak Algo Detection
**Decision**: Scan certificate bytes for MD5/SHA1 OIDs  
**Rationale**: Pragmatic approach; not ASN.1-correct but false positives unlikely in real certificates

### 5. Timestamp Presence Detection Only
**Decision**: Detect timestamps but don't fully validate RFC 3161  
**Rationale**: Full validation adds significant complexity for marginal benefit

## File Structure

```
CPP/7zip/
├── Crypto/
│   ├── 7zSignature.cpp    # Cross-platform CMS implementation (1286 lines)
│   └── 7zSignature.h      # Public interface (118 lines)
├── PropID.h               # +8 property IDs
├── Archive/
│   └── IArchive.h         # +3 operation results
└── Common/
    └── PropId.cpp         # VARTYPE mappings
```

## Data Structures

```cpp
struct CTimestampInfo {
  UString Authority;      // TSA name
  UString Timestamp;      // ISO 8601 timestamp
  bool IsValid;           // Timestamp signature verified
  bool HasTimestamp;      // Countersignature present
};

struct CCertInfo {
  UString Subject;        // Signer identity (CN)
  UString Issuer;         // Certificate Authority
  UString Thumbprint;     // SHA-1 fingerprint
  UString ExpiryDate;     // Expiration date
  bool IsExpired;         // Certificate expired
  bool IsWeakKey;         // Key < 2048 bits
  bool IsWeakAlgo;        // MD5 or SHA-1 signature
  bool IsNotCodeSigningCert;  // Missing code signing EKU
  CTimestampInfo TimestampInfo;
};
```

## Build Integration

### Makefile Changes (7zip_gcc.mak)

```makefile
# macOS
ifeq ($(UNAME_S),Darwin)
  LDFLAGS += -framework Security -framework CoreFoundation
endif

# Linux
ifeq ($(UNAME_S),Linux)
  LDFLAGS += -lssl -lcrypto
endif

# Windows (MinGW)
ifdef IS_MINGW
  LDFLAGS += -lcrypt32
endif
```

## Backward Compatibility

- Archives without signatures: Processed normally, no warnings
- Signature properties ignored by older 7-Zip versions (unknown property IDs)
- Default behavior: No signature (backward compatible)
- No changes to core 7z format structure
