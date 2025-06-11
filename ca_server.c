/*
 * Copyright (c) 2025 Luke, lcesarz@pm.me
 * SPDX-License-Identifier: MIT
 *
 * ca_server.c - Crtman daemon internals
 */
#include <utils.h>
#include "ca_server.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <Security/Security.h>
#include <pthread.h>

/*
 * @brief CADaemon object
 */
struct CADaemon
{
    const CAConfig  *cfg;
    SecKeyRef  ca_pk;
    X509      *ca_cert;
    CADaemonState  state;
    FILE *serial_fd;
    FILE *index_fd;
    FILE *crl_fd;
    pthread_mutex_t index_lock;
    pthread_mutex_t crl_lock;
};

/*
 * FWD declaration of all static helpers
 */
static CA_STATUS generate_self_signed_cert(CADaemon *ca, X509 **cert);
static void build_db_path(const CAConfig *cfg, const char *filename, char *out, size_t outlen);
static void ca_lock_index_file(CADaemon *ca);
static void ca_unlock_index_file(CADaemon *ca);
static void ca_lock_crl_file(CADaemon *ca);
static void ca_unlock_crl_file(CADaemon *ca);
static ASN1_INTEGER *ca_next_serial(CADaemon *ca);
static CA_STATUS ca_record_cert(CADaemon *ca, X509 *cert);
static CA_STATUS ca_generate_keypair(CADaemon *ca);
static CA_STATUS generate_self_signed_cert(CADaemon *ca, X509 **cert);
static CA_STATUS lazy_get_keypair(CADaemon *ca);
static X509_CRL *ca_build_crl_from_index(CADaemon *ca);
CA_STATUS ca_build_crl(CADaemon *ca, char **crl_pem_out);

/*
 * Public API implementation
 */
CA_STATUS ca_init(const CAConfig *cfg, CADaemon **out)
{
    CA_STATUS status = CA_OK;
    char path[PATH_MAX];

    REQUIRE_ACTION(cfg != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(out != NULL, return CA_ERR_BAD_PARAM;);

    CADaemon *ca = malloc(sizeof(struct CADaemon));
    REQUIRE_ACTION(ca != NULL, return CA_ERR_MEMORY;);

    ca->state = STARTING;
    ca->serial_fd = NULL;
    ca->index_fd = NULL;
    ca->crl_fd = NULL;

    // 0) Setup the config
    ca->cfg = cfg;

    // 1) Init the CA keys
    status = lazy_get_keypair(ca);
    REQUIRE_ACTION(status == CA_OK, return CA_ERR_INTERNAL;);

    // 2) Init serial file - used to track serial numbers
    build_db_path(ca->cfg, "serial", path, sizeof(path));
    ca->serial_fd = fopen(path, "a+");
    EXIT_IF(!ca->serial_fd, status, CA_ERR_INTERNAL, "Failed to open serial file");

    // 3) Init index file - used to track issued certs and revocation
    build_db_path(ca->cfg, "index.txt", path, sizeof(path));
    ca->index_fd = fopen(path, "a+");
    EXIT_IF(!ca->index_fd, status, CA_ERR_INTERNAL, "Failed to open serial file");

    // 4) Init CRL file - used for revocation persistence
    build_db_path(ca->cfg, "crl.pem", path, sizeof(path));
    ca->crl_fd = fopen(path, "a+");
    EXIT_IF(!ca->crl_fd, status, CA_ERR_INTERNAL, "Failed to open crl.pem file");

    // 5) Locks for the index && crl file - unnecessary for serial daemon
    pthread_mutex_init(&ca->index_lock, NULL);
    pthread_mutex_init(&ca->crl_lock, NULL);

    // 6) Good to go
    ca->state = RUNNING;
    *out = ca;

exit:
    if (status != CA_OK && ca)
    {
        FREE_IF_NOT_NULL(ca, free);
        FREE_IF_NOT_NULL(ca->serial_fd, fclose);
        FREE_IF_NOT_NULL(ca->index_fd, fclose);
        pthread_mutex_destroy(&ca->index_lock);
    }

    return status;
}

void ca_shutdown(CADaemon **ca)
{
    CADaemon *local = *ca;

    REQUIRE_ACTION(ca != NULL, return ;);
    REQUIRE_ACTION(local!= NULL, return ;);

    local->state = STOPPING;

    FREE_IF_NOT_NULL(local->ca_cert, X509_free);
    FREE_IF_NOT_NULL(local->serial_fd, fclose);
    FREE_IF_NOT_NULL(local->index_fd, fclose);
    pthread_mutex_destroy(&local->index_lock);

    local->ca_pk = NULL;

    FREE_IF_NOT_NULL(local, free);
}

CA_STATUS ca_get_ca_cert(CADaemon *ca, char **pem_out)
{
    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    int res = 0;
    CA_STATUS status = CA_OK;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(pem_out != NULL, return CA_ERR_BAD_PARAM;);

    bio = BIO_new(BIO_s_mem());
    REQUIRE_ACTION(bio != NULL, return CA_ERR_MEMORY;);

    res = PEM_write_bio_X509(bio, ca->ca_cert);
    EXIT_IF(!res, status, CA_ERR_INTERNAL, "Failed to PEM_write_bio_X509");

    BIO_get_mem_ptr(bio, &bptr);
    EXIT_IF(bptr == NULL, status, CA_ERR_INTERNAL, "Failed to get bio pointer");
    EXIT_IF(bptr->length  == 0, status, CA_ERR_INTERNAL, "Failed to get bio pointer");

    buf = malloc(bptr->length + 1);
    EXIT_IF(buf == NULL, status, CA_ERR_MEMORY, "Failed to allocate pem_out buffer");

    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    *pem_out = buf;
exit:

    FREE_IF_NOT_NULL(bio, BIO_free);
    if (status != CA_OK)
    {
        FREE_IF_NOT_NULL(buf, free);
    }

    return status;
}

CA_STATUS ca_issue_cert(CADaemon *ca,
                    const char *csr_pem,
                    unsigned    valid_days,
                    const char *profile,
                    char      **cert_pem_out,
                    char      **serial_out)
{
    int ret = 0;
    X509_REQ *req = NULL;
    EVP_PKEY *csr_pubkey = NULL;
    X509 *new_cert = NULL;
    ASN1_INTEGER *serial_asi = NULL;
    X509_NAME *issuer_name = NULL;
    unsigned char *tbs_der = NULL;
    int tbs_len = 0;
    CFDataRef tbs_data = NULL;
    CFErrorRef cfErr = NULL;
    CFDataRef sig_data = NULL;
    const uint8_t *sig_bytes = NULL;
    size_t sig_len = 0;
    X509_ALGOR *sig_alg = NULL;
    BIO *bio_out = NULL;
    BUF_MEM *bptr = NULL;
    unsigned char *pem_buf = NULL;
    BIGNUM *bn = NULL;
    char *serial_hex = NULL;
    CA_STATUS status = CA_OK;
    // TODO
    (void)profile;

    // 1) Parse the PEM CSR
    {
        BIO *mem = BIO_new_mem_buf((void *)csr_pem, -1);
        EXIT_IF(!mem, status, CA_ERR_INTERNAL, "Failed to allocate BIO mem buf");

        req = PEM_read_bio_X509_REQ(mem, NULL, NULL, NULL);
        BIO_free(mem);
        EXIT_IF(!req, status, CA_ERR_BAD_CSR, "Failed to read csr request");

        // Verify CSR signature
        csr_pubkey = X509_REQ_get_pubkey(req);
        EXIT_IF((!csr_pubkey || X509_REQ_verify(req, csr_pubkey) != 1), status, CA_ERR_BAD_CSR, "CSR Verification failed");
    }

    // 2) Build a new X509 certificate
    new_cert = X509_new();
    EXIT_IF(!new_cert, status, CA_ERR_INTERNAL, "Failed to allocate new X509");

    X509_set_version(new_cert, 2); // v3

    // 3) Assign serial number
    serial_asi = ca_next_serial(ca);
    EXIT_IF(!serial_asi, status, CA_ERR_INTERNAL, "Failed to assign serial number");

    X509_set_serialNumber(new_cert, serial_asi);

    // Convert serial → hex string for return (e.g. "01A3")
    {
        bn = ASN1_INTEGER_to_BN(serial_asi, NULL);
        EXIT_IF(!bn, status, CA_ERR_INTERNAL, "Failed to convert asn1INT to BN");

        char *hex = BN_bn2hex(bn);
        EXIT_IF(!hex, status, CA_ERR_INTERNAL, "Failed to BN_bn2hex");

        serial_hex = strdup(hex);
        DEBUG_LOG("serial_hex: %s", serial_hex);
        OPENSSL_free(hex);
        BN_free(bn);
        bn = NULL;
    }

    // 4) Issuer = CA’s subject
    issuer_name = X509_NAME_dup(X509_get_subject_name(ca->ca_cert));
    EXIT_IF(!issuer_name, status, CA_ERR_INTERNAL, "Failed to X509_NAME_dup");

    X509_set_issuer_name(new_cert, issuer_name);

    // 5) Validity
    X509_gmtime_adj(X509_get_notBefore(new_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(new_cert), (long)valid_days * 24 * 3600);

    // 6) Subject = CSR’s subject
    X509_set_subject_name(new_cert, X509_REQ_get_subject_name(req));

    // 7) Public key = CSR’s public key
    ret = X509_set_pubkey(new_cert, csr_pubkey);
    EXIT_IF(!ret, status, CA_ERR_INTERNAL, "Failed to X509_set_pubkey");

    // 8) signatureAlgorithm for TBSCertificate + outer
    sig_alg = X509_ALGOR_new();
    EXIT_IF(!sig_alg, status, CA_ERR_INTERNAL, "Failed to X509_ALGOR_new");

    X509_ALGOR_set0(sig_alg,
                    OBJ_nid2obj(NID_sha256WithRSAEncryption),
                    V_ASN1_NULL, NULL);

    ret = X509_set1_signature_algo(new_cert, sig_alg);
    EXIT_IF(!ret, status, CA_ERR_INTERNAL, "Failed to X509_set1_signature_algo");

    // We can free our local sig_alg; it was dup’d internally
    X509_ALGOR_free(sig_alg);
    sig_alg = NULL;

    // 9) DER-encode the TBSCertificate (everything except signatureValue)
    tbs_len = i2d_re_X509_tbs(new_cert, &tbs_der);
    EXIT_IF((tbs_len <= 0 || !tbs_der), status, CA_ERR_INTERNAL, "Failed to i2d_re_X509_tbs");

    // 10) Let SEP sign the TBSCertificate DER
    tbs_data = CFDataCreate(NULL, tbs_der, tbs_len);
    EXIT_IF(!tbs_data, status, CA_ERR_INTERNAL, "Failed to CFDataCreate");

    sig_data = SecKeyCreateSignature(ca->ca_pk,
                                     kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
                                     tbs_data,
                                     &cfErr);

    EXIT_IF(!sig_data, status, CA_ERR_INTERNAL, "Failed to SecKeyCreateSignature");

    sig_bytes = CFDataGetBytePtr(sig_data);
    sig_len   = CFDataGetLength(sig_data);

    // 11) Attach the signatureValue
    ret = X509_set1_signature_value(new_cert, sig_bytes, sig_len);
    EXIT_IF(!ret, status, CA_ERR_INTERNAL, "Failed to X509_set1_signature_value");

    CFRelease(sig_data);
    sig_data = NULL;

    // 12) Append a line to index.txt (issued)
    status = ca_record_cert(ca, new_cert);
    EXIT_IF_ERR(status, "Failed to ca_record_cert");

    // 13) Serialize new_cert → PEM
    bio_out = BIO_new(BIO_s_mem());
    EXIT_IF(!bio_out, status, CA_ERR_INTERNAL, "Failed to allocate bio_out");

    ret = PEM_write_bio_X509(bio_out, new_cert);
    EXIT_IF(!ret, status, CA_ERR_INTERNAL, "Failed to PEM_write_bio_X509");

    BIO_get_mem_ptr(bio_out, &bptr);
    EXIT_IF((!bptr || bptr->length == 0), status, CA_ERR_INTERNAL, "Failed to BIO_get_mem_ptr");

    pem_buf = malloc(bptr->length + 1);
    EXIT_IF(pem_buf == NULL, status, CA_ERR_INTERNAL, "Failed to allocate pem_buf");

    memcpy(pem_buf, bptr->data, bptr->length);
    pem_buf[bptr->length] = '\0';


    // 14) Return cert && serial hex
    *cert_pem_out = (char *)pem_buf;
    *serial_out = serial_hex;

    status = CA_OK;

exit:
    // Cleanup in reverse order, only if non-NULL:
    FREE_IF_NOT_NULL(bio_out, BIO_free);
    FREE_IF_NOT_NULL(sig_data, CFRelease);
    FREE_IF_NOT_NULL(tbs_data, CFRelease);
    FREE_IF_NOT_NULL(tbs_der, OPENSSL_free);
    FREE_IF_NOT_NULL(sig_alg, X509_ALGOR_free);
    FREE_IF_NOT_NULL(csr_pubkey, EVP_PKEY_free);
    FREE_IF_NOT_NULL(issuer_name, X509_NAME_free);
    FREE_IF_NOT_NULL(serial_asi, ASN1_INTEGER_free);
    FREE_IF_NOT_NULL(req, X509_REQ_free);
    if (status != CA_OK) {
        // On failure, free the partially constructed cert
        FREE_IF_NOT_NULL(new_cert, X509_free);
        // If serial_hex was allocated, free it
        FREE_IF_NOT_NULL(serial_hex, free);
        // On failure, free pem_buf
        FREE_IF_NOT_NULL(pem_buf, free);
    }

    return status;
}

CA_STATUS ca_revoke_cert(CADaemon *ca, const char *serial, int reason_code) {

    // Get current UTC time as YYYYMMDDHHMMSSZ
    char datestr[32];
    time_t now = time(NULL);
    struct tm gm;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(serial != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(ca->index_fd != NULL, return CA_ERR_INTERNAL;);

    // Lock the index file
    ca_lock_index_file(ca);

    if (!gmtime_r(&now, &gm)) {
        return CA_ERR_INTERNAL;
    }
    if (strftime(datestr, sizeof(datestr), "%Y%m%d%H%M%SZ", &gm) == 0) {
        return CA_ERR_INTERNAL;
    }

    // Append: R<TAB><date><TAB><reason><TAB><serial>\n
    fseek(ca->index_fd, 0, SEEK_END);
    fprintf(ca->index_fd, "R\t%s\t%s\t%d\n", datestr, serial, reason_code);
    fflush(ca->index_fd);
    fsync(fileno(ca->index_fd));

    // Unlock the index file
    ca_unlock_index_file(ca);

    return CA_OK;
}

CA_STATUS ca_get_crl(CADaemon *ca, char **crl_pem_out)
{
    CA_STATUS status = CA_OK;
    char *local_crl_pem = NULL;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(crl_pem_out != NULL, return CA_ERR_BAD_PARAM;);

    status = ca_build_crl(ca, &local_crl_pem);
    EXIT_IF_ERR(status, "Failed to build crl");

    *crl_pem_out = local_crl_pem;

exit:

    if (status != CA_OK)
    {
        FREE_IF_NOT_NULL(local_crl_pem, free);
    }

    return status;
}

/*
 * Static helper definitions
 */
static void build_db_path(const CAConfig *cfg, const char *filename, char *out, size_t outlen)
{
    snprintf(out, outlen, "%s/%s", cfg->db_dir, filename);
}

static void ca_lock_index_file(CADaemon *ca)
{
    REQUIRE_ACTION(ca != NULL, return;);

    pthread_mutex_lock(&ca->index_lock);
}

static void ca_unlock_index_file(CADaemon *ca)
{
    REQUIRE_ACTION(ca != NULL, return;);

    pthread_mutex_unlock(&ca->index_lock);
}

static void ca_lock_crl_file(CADaemon *ca)
{
    REQUIRE_ACTION(ca != NULL, return;);

    pthread_mutex_lock(&ca->crl_lock);
}

static void ca_unlock_crl_file(CADaemon *ca)
{
    REQUIRE_ACTION(ca != NULL, return;);

    pthread_mutex_unlock(&ca->crl_lock);
}


// Internal helper implementations
static ASN1_INTEGER *ca_next_serial(CADaemon *ca)
{
    unsigned long s = 1;

    REQUIRE_ACTION(ca != NULL, return NULL;);

    // Grab the index file lock
    ca_lock_index_file(ca);

    if (fscanf(ca->serial_fd, "%lx", &s) != 1)
    {
        fprintf(ca->serial_fd, "%lX", s + 1);
    }
    else
    {
        rewind(ca->serial_fd);
        fprintf(ca->serial_fd, "%lX", s + 1);
    }

    // Flush no matter what
    fflush(ca->serial_fd);
    fsync(fileno(ca->serial_fd));

    ASN1_INTEGER *asi = ASN1_INTEGER_new();

    if (!asi)
    {
        ca_unlock_index_file(ca);
        return NULL;
    }

    ASN1_INTEGER_set(asi, s);

    ca_unlock_index_file(ca);

    return asi;
}

static CA_STATUS ca_record_cert(CADaemon *ca, X509 *cert)
{
    CA_STATUS status = CA_OK;
    BIGNUM *bn = NULL;
    char *serial_hex = NULL;
    char *subject = NULL;
    char datestr[32];
    time_t now = time(NULL);
    struct tm gm;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(cert != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(ca->index_fd != NULL, return CA_ERR_INTERNAL;);

    ca_lock_index_file(ca);

    ASN1_INTEGER *asi = X509_get_serialNumber(cert);
    bn = ASN1_INTEGER_to_BN(asi, NULL);
    EXIT_IF(!bn, status, CA_ERR_INTERNAL, "Failed to ASN1_INTEGER_to_BN");

    serial_hex = BN_bn2hex(bn);
    EXIT_IF(!serial_hex, status, CA_ERR_INTERNAL, "Failed to BN_bn2hex");

    subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    EXIT_IF(!subject, status, CA_ERR_INTERNAL, "Failed to X509_NAME_oneline");

    // Grab the timestamp
    if (!gmtime_r(&now, &gm)) {
        return CA_ERR_INTERNAL;
    }
    if (strftime(datestr, sizeof(datestr), "%Y%m%d%H%M%SZ", &gm) == 0) {
        return CA_ERR_INTERNAL;
    }

    fseek(ca->index_fd, 0, SEEK_END);
    fprintf(ca->index_fd, "V\t%s\t%s\t%s\n", datestr, serial_hex, subject);
    fflush(ca->index_fd);
    fsync(fileno(ca->index_fd));
    status = CA_OK;


exit:

    ca_unlock_index_file(ca);

    FREE_IF_NOT_NULL(bn, BN_free);
    FREE_IF_NOT_NULL(serial_hex, OPENSSL_free);
    FREE_IF_NOT_NULL(subject, OPENSSL_free);

    return status ;
}

/*
 * @brief Generate SEP-backed CA keypair and a self-signed CA certificate.
 * Writes the new certificate to disk under cfg->db_dir/ca.cert.pem.
 *
 * @param ca     CADaemon context with cfg filled.
 * @return       CA_OK on success, error code on failure.
 */
static CA_STATUS ca_generate_keypair(CADaemon *ca)
{
    CFErrorRef cf_err = NULL;
    CFNumberRef key_size_num = NULL;
    CFStringRef label = NULL;
    CA_STATUS status = CA_OK;
    X509 *local_cert = NULL;
    char cert_path[PATH_MAX];
    int written = 0;
    CFMutableDictionaryRef priv_attrs = NULL;
    CFMutableDictionaryRef attributes = NULL;

    // Check input
    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);

    // Build the attr params
    key_size_num = CFNumberCreate(NULL, kCFNumberIntType, (int[]){3072});
    REQUIRE_ACTION(key_size_num != NULL, return CA_ERR_MEMORY;);

    label = CFStringCreateWithCString(NULL, ca->cfg->ca_label, kCFStringEncodingUTF8);
    EXIT_IF(label == NULL, status, CA_ERR_MEMORY, "Failed to CFStringCreateWithCString");

    // Private key attributes
    priv_attrs = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(priv_attrs, kSecAttrIsPermanent, kCFBooleanTrue);

    // Public attributes
    attributes = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, key_size_num);
    CFDictionaryAddValue(attributes, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(attributes, kSecAttrLabel, label);
    CFDictionaryAddValue(attributes, kSecPrivateKeyAttrs, priv_attrs);

    // Create the key
    ca->ca_pk = SecKeyCreateRandomKey(attributes, &cf_err);
    EXIT_IF(ca->ca_pk == NULL, status, CA_ERR_INTERNAL, "Failed to generate SEP key");

    // 2. Build self-signed CA certificate
    status = generate_self_signed_cert(ca, &local_cert);
    EXIT_IF(status != CA_OK, status, CA_ERR_INTERNAL, "Failed to generate the self signed cert");

    ca->ca_cert = local_cert;

    // 3. Build the path to the cert
    build_db_path(ca->cfg, "ca.cert.pem", cert_path, sizeof(cert_path));

    FILE *f = fopen(cert_path, "w");
    EXIT_IF(f == NULL, status, CA_ERR_INTERNAL, "Failed to open cert path");

    // 4. Write the cert
    written = PEM_write_X509(f, ca->ca_cert);
    if(written == 0)
    {
        status = CA_ERR_INTERNAL;
        DEBUG_LOG("Failed to write cert to file");
    }

    fclose(f);

exit:
    // Cleanup
    FREE_IF_NOT_NULL(attributes, CFRelease);
    FREE_IF_NOT_NULL(priv_attrs, CFRelease);
    FREE_IF_NOT_NULL(label, CFRelease);
    FREE_IF_NOT_NULL(key_size_num, CFRelease);

    // Edge failure after we allocate the cert
    if (status != CA_OK && local_cert)
    {
        X509_free(local_cert);
    }

    return status;
}

/**
 * Create a self-signed X509 certificate for the CA using its SEP key.
 */
static CA_STATUS generate_self_signed_cert(CADaemon *ca, X509 **cert)
{
    X509 *crt = NULL;
    ASN1_INTEGER *serial = NULL;
    X509_NAME *name = NULL;
    SecKeyRef pub_ref = NULL;
    CFErrorRef cf_err = NULL;
    CFDataRef pub_data = NULL;
    EVP_PKEY *evp_pub = NULL;
    CFDataRef data = NULL;
    const UInt8 *sig_bytes = NULL;
    unsigned int sig_len = 0;
    X509_ALGOR *sig_alg = NULL;
    unsigned char *tbs_der = NULL;
    int tbs_len = 0;
    CA_STATUS status = CA_OK;
    CFDataRef sig = NULL;
    RSA *rsa = NULL;
    ASN1_BIT_STRING *sig_bs = NULL;

    // Check input
    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);

    crt = X509_new();
    EXIT_IF(crt == NULL, status, CA_ERR_MEMORY, "Failed to allocate X509");

    X509_set_version(crt, 2);

    // Serial = 1
    serial = ASN1_INTEGER_new();
    EXIT_IF(serial == NULL, status, CA_ERR_MEMORY, "Failed to allocate serial int");

    ASN1_INTEGER_set(serial, 1);
    X509_set_serialNumber(crt, serial);

    // Validity
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), ca->cfg->default_validity);

    // Subject & Issuer = CN = ca_label
    name = X509_NAME_new();
    EXIT_IF(name == NULL, status, CA_ERR_MEMORY, "Failed to allocate X509 name");
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC,
        (unsigned char *)ca->cfg->ca_label, -1, -1, 0);
    X509_set_subject_name(crt, name);
    X509_set_issuer_name(crt, name);

    // Public key from SEP
    pub_ref = SecKeyCopyPublicKey(ca->ca_pk);
    EXIT_IF(pub_ref == NULL, status, CA_ERR_MEMORY, "Failed to get pubref");

    pub_data = SecKeyCopyExternalRepresentation(pub_ref, &cf_err);
    EXIT_IF(pub_data == NULL, status, CA_ERR_INTERNAL, "Failed to copy pub key ref");

    const unsigned char *p = CFDataGetBytePtr(pub_data);
    size_t len = CFDataGetLength(pub_data);

    rsa = d2i_RSAPublicKey(NULL, &p, len);
    EXIT_IF(rsa == NULL, status, CA_ERR_INTERNAL, "Failed to get rsa from sep");

    evp_pub = EVP_PKEY_new();
    EXIT_IF(!EVP_PKEY_assign_RSA(evp_pub, rsa), status, CA_ERR_INTERNAL, "Failed to convert rsa to der");


    int res = X509_set_pubkey(crt, evp_pub);
    EXIT_IF(res == 0, status, CA_ERR_INTERNAL, "Failed to set pub key in crt");
    EXIT_IF(res == 0, status, CA_ERR_INTERNAL, "Failed to fake sign the pub cert");

    // X509 now owns this
    EVP_PKEY_free(evp_pub);
    evp_pub = NULL;

    // 2) Create your AlgorithmIdentifier for SHA256‐RSA:
    sig_alg = X509_ALGOR_new();
    X509_ALGOR_set0(sig_alg, OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL);

    // 3) Inject into both TBSCertificate and outer signatureAlgorithm:
    EXIT_IF(!X509_set1_signature_algo(crt, sig_alg), status, CA_ERR_INTERNAL, "Failed to set signature algorithm in X509.");

    // Sign TBSCertificate
    tbs_len = i2d_re_X509_tbs(crt, &tbs_der);
    EXIT_IF(tbs_len <= 0, status, CA_ERR_INTERNAL, "tbs_len <= 0");
    EXIT_IF(tbs_der == NULL, status, CA_ERR_INTERNAL, "tbs_der is NULL");

    data = CFDataCreate(NULL, tbs_der, tbs_len);
    sig = SecKeyCreateSignature(ca->ca_pk,
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
        data, &cf_err);
    EXIT_IF(sig == NULL, status, CA_ERR_INTERNAL, "Faield to create signature on tbs");

    sig_bytes = CFDataGetBytePtr(sig);
    sig_len = (int)CFDataGetLength(sig);

    // 6) Inject the signature bytes:
    if (!X509_set1_signature_value(crt, sig_bytes, sig_len)) {
        // handle error
    }

    // 7) Now you have a fully‐populated X509.
    //    Serialize with i2d_X509 or write PEM.
    unsigned char *out_der = NULL;
    int out_len = i2d_X509(crt, &out_der);
    EXIT_IF(out_len <= 0, status, CA_ERR_INTERNAL, "Failed to i2d_X509");

    *cert = crt;

exit:

    FREE_IF_NOT_NULL(data, CFRelease);
    FREE_IF_NOT_NULL(sig, CFRelease);
    FREE_IF_NOT_NULL(rsa, RSA_free);
    FREE_IF_NOT_NULL(serial, ASN1_INTEGER_free);
    FREE_IF_NOT_NULL(name, X509_NAME_free);
    FREE_IF_NOT_NULL(tbs_der, OPENSSL_free);
    FREE_IF_NOT_NULL(pub_ref, CFRelease);
    FREE_IF_NOT_NULL(pub_data, CFRelease);
    FREE_IF_NOT_NULL(sig_bs, ASN1_BIT_STRING_free);
    FREE_IF_NOT_NULL(sig_alg, X509_ALGOR_free);

    if (status != CA_OK)
    {
        FREE_IF_NOT_NULL(crt, X509_free);
    }

    return status;

}

static CA_STATUS lazy_get_keypair(CADaemon *ca)
{
    CA_STATUS status = CA_OK;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(ca->cfg != NULL, return CA_ERR_BAD_PARAM;);

    if (ca->cfg->provision_key)
    {
        status = ca_generate_keypair(ca);
    }
    else
    {
        CFMutableDictionaryRef query= CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
        CFDictionaryAddValue(query, kSecClass, kSecClassKey);
        CFDictionaryAddValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
        CFDictionaryAddValue(query, kSecAttrLabel, ca->cfg->ca_label);
        CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);

        CFTypeRef result = NULL;
        OSStatus res = SecItemCopyMatching(query, &result);
        CFRelease(query);

        if (res == errSecSuccess)
        {
            ca->ca_pk = (SecKeyRef)result;
        }
        else
        {
            status = CA_ERR_INTERNAL;
        }
    }

    return status;
}

static X509_CRL *ca_build_crl_from_index(CADaemon *ca)
{
    CA_STATUS status = CA_OK;
    ASN1_ENUMERATED *ent = NULL;
    int err = 0;

    REQUIRE_ACTION(ca != NULL, return NULL;);
    REQUIRE_ACTION(ca->index_fd != NULL, return NULL;);

    X509_CRL *crl = X509_CRL_new();
    REQUIRE_ACTION(crl != NULL, return NULL;);

    // v2 CRL
    REQUIRE_ACTION(X509_CRL_set_version(crl, 1) != 0, goto exit;);

    // Issuer = CA subject
    REQUIRE_ACTION(X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca->ca_cert)) != 0, goto exit;);

    // Set lastUpdate = now, nextUpdate = now + 7 days
    X509_gmtime_adj(X509_CRL_get_lastUpdate(crl), 0);
    X509_gmtime_adj(X509_CRL_get_nextUpdate(crl), 7*24*3600);

    char line[1024];

    ca_lock_index_file(ca);

    long reset = ftell(ca->index_fd);
    EXIT_IF(reset == -1, status, CA_ERR_INTERNAL, "Failed to reset the file");
    EXIT_IF(fseek(ca->index_fd, 0, SEEK_SET) != 0, status, CA_ERR_INTERNAL, "Failed to reset the file");

    while (fgets(line, sizeof(line), ca->index_fd)) {
        if (line[0] != 'R')
        {
            continue;  // skip non-revocations
        }

        // tokenize: R \t date \t reason \t serial
        char *tok = strtok(line, "\t");

        // tok == "R"
        tok = strtok(NULL, "\t");      // date

        if (!tok)
        {
            err += 1;
            continue;
        }
        char datebuf[32];
        strlcpy(datebuf, tok, sizeof(datebuf));

        tok = strtok(NULL, "\t");      // reason
        if (!tok)
        {
            err += 1;
            continue;
        }
        int reason = atoi(tok);

        tok = strtok(NULL, "\t\r\n");  // serial
        if (!tok)
        {
            err += 1;
            continue;
        }
        char *serial = tok;

        // Build X509_REVOKED
        X509_REVOKED *rev = X509_REVOKED_new();
        if (!rev)
        {
            err += 1;
            continue;
        }

        // serial
        ASN1_INTEGER *asi = s2i_ASN1_INTEGER(NULL, serial);
        if (!asi)
        {
            err += 1;
            X509_REVOKED_free(rev);
            continue;
        }
        X509_REVOKED_set_serialNumber(rev, asi);

        // revocationDate
        ASN1_TIME *rt = ASN1_TIME_new();
        if (!rt)
        {
            err += 1;
            ASN1_INTEGER_free(asi);
            X509_REVOKED_free(rev);
            continue;
        }

        if (!ASN1_TIME_set_string(rt, datebuf))
        {
            err += 1;
            ASN1_TIME_free(rt);
            ASN1_INTEGER_free(asi);
            X509_REVOKED_free(rev);
            continue;
        }
        X509_REVOKED_set_revocationDate(rev, rt);

        // CRLReason extension Needs to be ASN1_EXTENSION
        ent = ASN1_ENUMERATED_new();
        if (!ent)
        {
            err += 1;
            continue;
        }
        if (!ASN1_ENUMERATED_set(ent, reason))
        {
            err += 1;
            ASN1_ENUMERATED_free(ent);
            continue;
        }
        // reason is the CRLReason enum (0–10)
        X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason,
                                 ent, 0, 0);
        ASN1_ENUMERATED_free(ent);

        // Add to CRL
        X509_CRL_add0_revoked(crl, rev);
        // rev now owned by crl
    }
    EXIT_IF(fseek(ca->index_fd, reset, SEEK_SET) != 0, status, CA_ERR_INTERNAL, "Failed to reset file position after reading");

    // TODO: This should be logged to the system not just debug logged
    if (err > 0)
    {
        DEBUG_LOG("Encountered %d errors when parsing index for CRL", err);
    }

exit:
    ca_unlock_index_file(ca);
    if (status == CA_OK)
    {
        return crl;
    }
    else
    {
        X509_CRL_free(crl);
        return NULL;
    }
}

extern CA_STATUS ca_build_crl(CADaemon *ca, char **crl_pem_out)
{

    CA_STATUS status     = CA_OK;
    X509_CRL   *crl      = NULL;
    unsigned char *tbs_der    = NULL;
    int         tbs_len  = 0;
    CFDataRef   tbs_data = NULL;
    CFErrorRef  cfErr    = NULL;
    CFDataRef   sig_data = NULL;
    const uint8_t *sig_bytes = NULL;
    size_t      sig_len  = 0;
    X509_ALGOR *sig_alg  = NULL;
    BIO        *bio_mem  = NULL;
    BUF_MEM    *bptr     = NULL;
    unsigned char *pem_buf = NULL;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(ca->crl_fd != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(crl_pem_out != NULL, return CA_ERR_BAD_PARAM;);

    // 1) Build CRL object (unsigned)
    crl = ca_build_crl_from_index(ca);
    EXIT_IF(crl == NULL, status, CA_ERR_INTERNAL, "Failed ca_build_crl_from_index");

    // 1.5) Give the crl a bogus signature since OSSL makes us have this to DER encode it
    X509_ALGOR *tbs_alg = X509_ALGOR_new();
    X509_ALGOR_set0(tbs_alg, OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL);

    // Duplicate into the TBSCertList and outer fields:
    X509_CRL_set1_signature_algo(crl, tbs_alg);
    // free the local copy now:
    X509_ALGOR_free(tbs_alg);

    // 2) DER-encode the TBSCertList
    tbs_len = i2d_re_X509_CRL_tbs(crl, &tbs_der);
    EXIT_IF(tbs_len <= 0, status, CA_ERR_INTERNAL, "Failed to i2d_re_X509_crl_tbs len check");
    EXIT_IF(tbs_der == NULL, status, CA_ERR_INTERNAL, "Failed to i2d_re_X509_crl_tbs null check");

    // 3) Sign via Secure Enclave
    tbs_data = CFDataCreate(NULL, tbs_der, tbs_len);
    sig_data = SecKeyCreateSignature(ca->ca_pk,
        kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
        tbs_data, &cfErr);
    EXIT_IF(!sig_data, status, CA_ERR_INTERNAL, "Failed to SecKeyCreateSignature");

    sig_bytes = CFDataGetBytePtr(sig_data);
    sig_len   = CFDataGetLength(sig_data);

    // 4) Inject signatureAlgorithm + signatureValue
    sig_alg = X509_ALGOR_new();
    EXIT_IF(!sig_alg, status, CA_ERR_INTERNAL, "Failed to allocate x509");

    X509_ALGOR_set0(sig_alg,
        OBJ_nid2obj(NID_sha256WithRSAEncryption),
        V_ASN1_NULL, NULL);
    // This duplicates into both tbs and outer fields
    EXIT_IF(!X509_CRL_set1_signature_algo(crl, sig_alg), status, CA_ERR_INTERNAL, "Failed to X509_CRL_set1_signature_algo");
    // And attach the raw signature bytes
    EXIT_IF(!X509_CRL_set1_signature_value(crl, sig_bytes, sig_len), status, CA_ERR_INTERNAL, "Failed to X509_CRL_set1_signature_value");

    // 5) Write signed CRL to disk
    ca_lock_crl_file(ca);
    EXIT_IF(!PEM_write_X509_CRL(ca->crl_fd, crl), status, CA_ERR_INTERNAL, "Failed to PEM_write_X509_CRL");
    ca_unlock_crl_file(ca);
    fflush(ca->crl_fd);
    fsync(fileno(ca->crl_fd));

    // 6) Serialize to PEM in memory
    bio_mem = BIO_new(BIO_s_mem());
    EXIT_IF(!bio_mem, status, CA_ERR_MEMORY, "Failed to allocate BIO");

    EXIT_IF(!PEM_write_bio_X509_CRL(bio_mem, crl), status, CA_ERR_INTERNAL, "Failed to PEM_write_bio_X509_CRL");

    BIO_get_mem_ptr(bio_mem, &bptr);
    EXIT_IF((!bptr || bptr->length == 0), status, CA_ERR_INTERNAL, "Failed to BIO_get_mem_ptr");

    pem_buf = malloc(bptr->length + 1);
    EXIT_IF(pem_buf == NULL, status, CA_ERR_MEMORY, "Failed to allocate pem_buf");

    memcpy(pem_buf, bptr->data, bptr->length);
    pem_buf[bptr->length] = '\0';

    *crl_pem_out = (char *)pem_buf;

exit:
    if (status != CA_OK)
    {
        FREE_IF_NOT_NULL(pem_buf, free);
    }
    FREE_IF_NOT_NULL(tbs_der, OPENSSL_free);
    FREE_IF_NOT_NULL(tbs_data, CFRelease);
    FREE_IF_NOT_NULL(sig_data, CFRelease);
    FREE_IF_NOT_NULL(sig_alg, X509_ALGOR_free);
    FREE_IF_NOT_NULL(crl, X509_CRL_free);
    FREE_IF_NOT_NULL(bio_mem, BIO_free);

    return status;
}
