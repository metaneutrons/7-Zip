#ifndef ZIP7_INC_CERT_UTILS_H
#define ZIP7_INC_CERT_UTILS_H

#include "../../Common/MyString.h"

// Forward declarations
typedef struct x509_st X509;

namespace NCrypto {

struct CCertificateInfo {
  AString Subject;
  AString Issuer;
  AString ValidFrom;
  AString ValidTo;
  bool IsExpired;
  bool IsSelfSigned;
};

// Cross-platform certificate parsing using OpenSSL
bool ParseCertificateFromPKCS12(const Byte *data, size_t size, const char *password, CCertificateInfo &certInfo);
bool ExtractCertificateInfo(X509 *cert, CCertificateInfo &certInfo);

}

#endif
