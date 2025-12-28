#include "StdAfx.h"
#include "CertUtils.h"

#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

namespace NCrypto {

bool ParseCertificateFromPKCS12(const Byte *data, size_t size, const char *password, CCertificateInfo &certInfo)
{
  (void)data; // Suppress unused warning
  printf("DEBUG: ParseCertificateFromPKCS12 called with size=%zu, password=%s\n", size, password ? password : "NULL");
  
  // For debugging, just return fake certificate info without using OpenSSL
  certInfo.Subject = "/CN=Debug Certificate";
  certInfo.Issuer = "/CN=Debug CA";
  certInfo.ValidFrom = "Jan 1 2024";
  certInfo.ValidTo = "Jan 1 2025";
  certInfo.IsExpired = false;
  certInfo.IsSelfSigned = true;
  
  printf("DEBUG: Returning fake certificate info\n");
  return true;
}

bool ExtractCertificateInfo(X509 *cert, CCertificateInfo &certInfo)
{
  if (!cert) return false;
  
  char buf[512];
  
  // Subject
  X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
  certInfo.Subject = buf;
  
  // Issuer
  X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
  certInfo.Issuer = buf;
  
  // Check if self-signed (simplified check)
  certInfo.IsSelfSigned = (certInfo.Subject == certInfo.Issuer);
  
  // Validity dates
  const ASN1_TIME *notBefore = X509_get0_notBefore(cert);
  const ASN1_TIME *notAfter = X509_get0_notAfter(cert);
  
  if (notBefore) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio) {
      ASN1_TIME_print(bio, notBefore);
      int len = BIO_pending(bio);
      if (len > 0 && len < (int)sizeof(buf)) {
        BIO_read(bio, buf, len);
        buf[len] = 0;
        certInfo.ValidFrom = buf;
      }
      BIO_free(bio);
    }
  }
  
  if (notAfter) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio) {
      ASN1_TIME_print(bio, notAfter);
      int len = BIO_pending(bio);
      if (len > 0 && len < (int)sizeof(buf)) {
        BIO_read(bio, buf, len);
        buf[len] = 0;
        certInfo.ValidTo = buf;
      }
      BIO_free(bio);
    }
  }
  
  // Check expiration (simplified - just compare if we have valid dates)
  certInfo.IsExpired = false; // We'll just show the dates, let user determine expiration
  
  return true;
}

}
