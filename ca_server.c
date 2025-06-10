// ca_server.c
//
// Luke Cesarz
//
// lcesarz@pm.me
//

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
#include <openssl/err.h>
#include <Security/Security.h>

/*
 * @brief CADaemon object
 */
struct CADaemon
{
    const CAConfig  *cfg;
    SecKeyRef  ca_pk;
    X509      *ca_cert;
    CADaemonState  state;
};

static void build_db_path(const CAConfig *cfg, const char *filename, char *out, size_t outlen) {
    snprintf(out, outlen, "%s/%s", cfg->db_dir, filename);
}

static CA_STATUS generate_self_signed_cert(CADaemon *ca, X509 **cert);

// Internal helper implementations

ASN1_INTEGER *ca_next_serial(CADaemon *ca)
{
    char path[PATH_MAX];
    build_db_path(ca->cfg, "serial", path, sizeof(path));
    FILE *f = fopen(path, "r+");
    unsigned long s = 1;
    if (!f) {
        f = fopen(path, "w");
        REQUIRE_ACTION(f != 0, return NULL;);

        fprintf(f, "%lX", s + 1);
        fclose(f);
    }
    else
    {
        if (fscanf(f, "%lx", &s) != 1)
        {
            DEBUG_LOG("Failed reading file %d", s);
            fclose(f);
            return NULL;
        }

        rewind(f);
        fprintf(f, "%lX", s + 1);
        fclose(f);
    }

    ASN1_INTEGER *asi = ASN1_INTEGER_new();

    if (!asi)
    {
        return NULL;
    }

    ASN1_INTEGER_set(asi, s);

    return asi;
}

CA_STATUS ca_record_cert(CADaemon *ca, X509 *cert)
{
    // TODO: format
    CA_STATUS status = CA_OK;
    char path[PATH_MAX];
    FILE *f = NULL;
    BIGNUM *bn = NULL;
    char *hex = NULL;
    char *subject = NULL;

    build_db_path(ca->cfg, "index.txt", path, sizeof(path));

    f = fopen(path, "a");
    EXIT_IF(!f, status, CA_ERR_INTERNAL, "Failed to open index file");

    ASN1_INTEGER *asi = X509_get_serialNumber(cert);
    bn = ASN1_INTEGER_to_BN(asi, NULL);
    EXIT_IF(!bn, status, CA_ERR_INTERNAL, "Failed to ASN1_INTEGER_to_BN");

    hex = BN_bn2hex(bn);
    EXIT_IF(!hex, status, CA_ERR_INTERNAL, "Failed to BN_bn2hex");

    subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    EXIT_IF(!subject, status, CA_ERR_INTERNAL, "Failed to X509_NAME_oneline");

    fprintf(f, "V			%s	%s\n", hex, subject);
    status = CA_OK;

exit:
    if (f)
    {
        fclose(f);
    }
    FREE_IF_NOT_NULL(bn, BN_free);
    FREE_IF_NOT_NULL(hex, OPENSSL_free);
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
    EXIT_IF(ca->ca_pk == NULL, status, CA_ERR_INTERNAL, "Failed to generate SEP key: %s", cf_err ? CFErrorCopyDescription(cf_err) : CFSTR("unknown error"));

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

CA_STATUS ca_init(const CAConfig *cfg, CADaemon **out)
{
    CA_STATUS status = CA_OK;

    REQUIRE_ACTION(cfg != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(out != NULL, return CA_ERR_BAD_PARAM;);

    CADaemon *ca = malloc(sizeof(struct CADaemon));
    REQUIRE_ACTION(ca != NULL, return CA_ERR_MEMORY;);

    ca->state = STARTING;

    // Setup the config
    ca->cfg = cfg;

    status = lazy_get_keypair(ca);
    REQUIRE_ACTION(status == CA_OK, return CA_ERR_INTERNAL;);

    // TODO verify the ca is setup before returning success
    ca->state = RUNNING;
    *out = ca;

    return CA_OK;
}

void ca_shutdown(CADaemon **ca)
{
    CADaemon *local = *ca;

    REQUIRE_ACTION(ca != NULL, return ;);
    REQUIRE_ACTION(local!= NULL, return ;);

    local->state = STOPPING;

    FREE_IF_NOT_NULL(local->ca_cert, X509_free);

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
    // TODO: test this function
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
    char *pem_str = NULL;
    BIGNUM *bn = NULL;
    char *serial_hex = NULL;
    CA_STATUS status = CA_OK;

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
                    OBJ_nid2obj(NID_ecdsa_with_SHA256),
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
