#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "ca_client.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

/**
 * Generate an RSA key pair and a CSR, returning the CSR as a PEM string.
 * Caller must free() the returned string.
 */
static char *generate_test_csr(const char *common_name)
{
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    X509_REQ *req = NULL;
    X509_NAME *name = NULL;
    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;
    char *csr_pem = NULL;

    // 1) Generate RSA key
    bn = BN_new();
    if (!bn || !BN_set_word(bn, RSA_F4)) {
        goto cleanup;
    }

    rsa = RSA_new();
    if (!rsa || !RSA_generate_key_ex(rsa, 2048, bn, NULL)) {
        goto cleanup;
    }

    pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_assign_RSA(pkey, rsa)) {
        goto cleanup;
    }
    rsa = NULL;  // pkey owns it now

    // 2) Create CSR
    req = X509_REQ_new();
    if (!req) {
        goto cleanup;
    }

    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, pkey);

    // 3) Set subject name
    name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC,
                               (unsigned char *)common_name, -1, -1, 0);

    // 4) Sign the CSR with the private key
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
        goto cleanup;
    }

    // 5) Convert to PEM
    bio = BIO_new(BIO_s_mem());
    if (!bio || !PEM_write_bio_X509_REQ(bio, req)) {
        goto cleanup;
    }

    BIO_get_mem_ptr(bio, &bptr);
    csr_pem = malloc(bptr->length + 1);
    if (csr_pem) {
        memcpy(csr_pem, bptr->data, bptr->length);
        csr_pem[bptr->length] = '\0';
    }

cleanup:
    if (bio) BIO_free(bio);
    if (req) X509_REQ_free(req);
    if (pkey) EVP_PKEY_free(pkey);
    if (rsa) RSA_free(rsa);
    if (bn) BN_free(bn);

    return csr_pem;
}

int main(void) {
    CAClient *client = ca_client_init();
    if (!client) {
        fprintf(stderr, "Failed to initialize CA client\n");
        return 1;
    }

    // 1) Fetch the CA certificate
    char *ca_pem = NULL;
    uint32_t ca_len = 0;
    if (ca_client_get_ca_cert(client, &ca_pem, &ca_len) == CA_OK) {
        printf("--- CA Certificate (len %u) ---\n%s\n", ca_len, ca_pem);
        free(ca_pem);
    } else {
        fprintf(stderr, "ca_client_get_ca_cert failed\n");
    }

    // 2) Generate a real CSR and issue a certificate
    char *csr_pem = generate_test_csr("test.example.com");
    if (!csr_pem) {
        fprintf(stderr, "Failed to generate test CSR\n");
        ca_client_shutdown(client);
        return 1;
    }
    printf("--- Generated CSR ---\n%s\n", csr_pem);

    char *issued_pem = NULL;
    uint32_t issued_len = 0;
    char *serial = NULL;
    uint32_t serial_len = 0;
    if (ca_client_issue_cert(client,
                              csr_pem,
                              365,
                              "server",
                              &issued_pem,
                              &issued_len,
                              &serial,
                              &serial_len) == CA_OK) {
        printf("--- Issued Certificate (len %u) ---\n%s\n", issued_len, issued_pem);
        printf("Serial: %s\n", serial);
    } else {
        fprintf(stderr, "ca_client_issue_cert failed\n");
    }
    free(csr_pem);

    // 3) Revoke the issued certificate (if we got one)
    if (serial) {
        if (ca_client_revoke_cert(client, serial, 1) == CA_OK) {
            printf("Serial %s revoked (reason 1)\n", serial);
        } else {
            fprintf(stderr, "ca_client_revoke_cert failed\n");
        }
    }

    // 4) Fetch the CRL
    char *crl_pem = NULL;
    uint32_t crl_len = 0;
    if (ca_client_get_crl(client, &crl_pem, &crl_len) == CA_OK) {
        printf("--- CRL (len %u) ---\n%s\n", crl_len, crl_pem);
        free(crl_pem);
    } else {
        fprintf(stderr, "ca_client_get_crl failed\n");
    }

    // Cleanup
    free(issued_pem);
    free(serial);
    ca_client_shutdown(client);
    return 0;
}
