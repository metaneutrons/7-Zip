#include <stdio.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

int main() {
    // Initialize OpenSSL
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    
    // Open certificate file
    FILE* fp = fopen("test_with_pass.p12", "rb");
    if (!fp) {
        printf("Cannot open certificate file\n");
        return 1;
    }
    
    // Read PKCS#12
    PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
    fclose(fp);
    
    if (!p12) {
        printf("Cannot parse PKCS#12 file\n");
        return 1;
    }
    
    // Parse PKCS#12
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    
    int result = PKCS12_parse(p12, "testpass", &pkey, &cert, NULL);
    PKCS12_free(p12);
    
    if (!result || !pkey || !cert) {
        printf("Cannot parse PKCS#12 contents\n");
        if (pkey) EVP_PKEY_free(pkey);
        if (cert) X509_free(cert);
        return 1;
    }
    
    // Validate key matches certificate
    if (!X509_check_private_key(cert, pkey)) {
        printf("Private key does not match certificate\n");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return 1;
    }
    
    printf("Certificate loaded successfully!\n");
    
    // Get certificate subject
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    if (subj) {
        printf("Subject: %s\n", subj);
        OPENSSL_free(subj);
    }
    
    // Cleanup
    EVP_PKEY_free(pkey);
    X509_free(cert);
    
    return 0;
}
