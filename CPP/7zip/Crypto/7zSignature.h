// 7zSignature.h

#ifndef ZIP7_INC_7Z_SIGNATURE_H
#define ZIP7_INC_7Z_SIGNATURE_H

#include "../../Common/MyString.h"
#include "../../Common/MyBuffer.h"
#include "../../Common/MyVector.h"
#include "../Archive/IArchive.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/cms.h>

#ifdef __APPLE__
#include <Security/Security.h>
#elif defined(_WIN32)
#include <wincrypt.h>
#endif

namespace NCrypto {

namespace NRevocationMode {
  enum EEnum { kSoft = 0, kHard = 1, kOff = 2 };
}

namespace NSigVerifyLevel {
  enum EEnum { kDisabled = -1, kStrict = 0, kMixed = 1, kPermissive = 2, kWarn = 3 };
}

namespace NDigSigLevel {
  enum EEnum { kBoth = 0, kArchiveOnly = 1, kFileOnly = 2 };
}

/**
 * Timestamp information extracted from CMS countersignature.
 * Used for long-term signature validity verification.
 */
struct CTimestampInfo
{
  UString Authority;      // TSA (Time Stamping Authority) name
  UString Timestamp;      // ISO 8601 formatted timestamp
  bool IsValid;           // True if timestamp signature verified
  bool HasTimestamp;      // True if countersignature present
  
  CTimestampInfo(): IsValid(false), HasTimestamp(false) {}
};

/**
 * Certificate information extracted during signature verification.
 * Contains identity info and security warnings.
 */
struct CCertInfo
{
  UString Subject;        // Certificate subject (signer identity)
  UString Issuer;         // Certificate issuer (CA)
  UString Thumbprint;     // SHA-1 fingerprint (hex)
  UString ExpiryDate;     // Certificate expiration date
  bool IsExpired;         // True if certificate has expired
  bool IsWeakKey;         // True if key < 2048 bits
  bool IsWeakAlgo;        // True if signed with MD5/SHA1
  bool IsNotCodeSigningCert;  // True if missing code signing EKU (warning only)
  CTimestampInfo TimestampInfo;

  CCertInfo(): IsExpired(false), IsWeakKey(false), IsWeakAlgo(false), IsNotCodeSigningCert(false) {}
};

/**
 * Cross-platform digital signature handler for CMS/PKCS#7 signatures.
 * 
 * Platform implementations:
 * - macOS: Security.framework (CMSEncoder/CMSDecoder)
 * - Windows: CryptoAPI (CryptSignMessage/CryptVerifyDetachedMessageSignature)
 * - Linux: OpenSSL (CMS_sign/CMS_verify)
 * 
 * Features:
 * - Certificate loading from PFX/P12 files
 * - System keychain/certificate store selection (macOS/Windows)
 * - Custom trust store support
 * - Revocation checking (soft-fail default, configurable)
 * - Weak algorithm/key detection
 * - Timestamp extraction
 */
class CSignatureHandler
{
public:
  CSignatureHandler();
  ~CSignatureHandler();

  // File-based identity loading
  HRESULT LoadIdentity(const wchar_t *certPath, const wchar_t *keyPath);
  
  // Set password for P12/PFX file
  void SetPassword(const UString &password) { _password = password; }
  
  // System keychain/store selection (macOS/Windows only)
  // selector: "list" = enumerate, "sha1:XXX" = by thumbprint, else = name match
  HRESULT SelectIdentity(const wchar_t *selector, CObjectVector<CCertInfo> *outList = NULL);
  
  // Unified: auto-detect file vs keychain selector
  HRESULT LoadOrSelectIdentity(const wchar_t *certPathOrSelector, const wchar_t *keyPath = NULL);
  
  HRESULT SetTrustStore(const wchar_t *trustStorePath);
  HRESULT SetSignatureAlgorithm(const UString &algoName);
  HRESULT GetSupportedAlgorithms(UStringVector &algos);

  HRESULT Sign(const Byte *data, size_t size, CByteBuffer &signature);
  HRESULT Verify(const Byte *data, size_t size, const Byte *sig, size_t sigLen,
                 Int32 &result, CCertInfo &certInfo);
  HRESULT GetCertificateChain(CByteBuffer &certStore);
  
  void SetRevocationMode(NRevocationMode::EEnum mode) { _revocationMode = mode; }

private:
  UString _algorithm;
  UString _trustStorePath;
  UString _password;
  NRevocationMode::EEnum _revocationMode;

  // OpenSSL objects (used for file-based certificates)
  EVP_PKEY *_pkey;
  X509 *_cert;
  X509_STORE *_trustStore;
  bool _useOpenSSL;

#ifdef __APPLE__
  SecIdentityRef _identity;
  SecPolicyRef _trustPolicy;
#elif defined(_WIN32)
  HCERTSTORE _hStore;
  PCCERT_CONTEXT _pCertContext;
#endif
};

}

#endif
