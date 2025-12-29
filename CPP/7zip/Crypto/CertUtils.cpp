#include "StdAfx.h"
#include "CertUtils.h"

#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/cms.h>

namespace NCrypto {

bool ParseCertificateFromPKCS12(const Byte *data, size_t size, const char *password, CCertificateInfo &certInfo)
{
  if (!data || size == 0) return false;
  
  BIO *bio = BIO_new_mem_buf(data, (int)size);
  if (!bio) return false;
  
  PKCS12 *p12 = d2i_PKCS12_bio(bio, NULL);
  BIO_free(bio);
  if (!p12) return false;
  
  EVP_PKEY *pkey = NULL;
  X509 *cert = NULL;
  STACK_OF(X509) *ca = NULL;
  
  bool result = false;
  if (PKCS12_parse(p12, password ? password : "", &pkey, &cert, &ca)) {
    if (cert) {
      result = ExtractCertificateInfo(cert, certInfo);
      X509_free(cert);
    }
    if (pkey) EVP_PKEY_free(pkey);
    if (ca) sk_X509_pop_free(ca, X509_free);
  }
  
  PKCS12_free(p12);
  return result;
}

bool ParseCertificateFromCMS(const Byte *data, size_t size, CCertificateInfo &certInfo)
{
  if (!data || size == 0) return false;
  
  BIO *bio = BIO_new_mem_buf(data, (int)size);
  if (!bio) return false;
  
  CMS_ContentInfo *cms = d2i_CMS_bio(bio, NULL);
  BIO_free(bio);
  if (!cms) return false;
  
  STACK_OF(X509) *certs = CMS_get1_certs(cms);
  bool result = false;
  
  if (certs && sk_X509_num(certs) > 0) {
    X509 *cert = sk_X509_value(certs, 0); // Use first certificate
    if (cert) {
      result = ExtractCertificateInfo(cert, certInfo);
    }
  }
  
  if (certs) sk_X509_pop_free(certs, X509_free);
  CMS_ContentInfo_free(cms);
  return result;
}

bool ParseCertificateFromX509(const Byte *data, size_t size, CCertificateInfo &certInfo)
{
  if (!data || size == 0) return false;
  
  const unsigned char *p = data;
  X509 *cert = d2i_X509(NULL, &p, (long)size);
  if (!cert) return false;
  
  bool result = ExtractCertificateInfo(cert, certInfo);
  X509_free(cert);
  return result;
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
