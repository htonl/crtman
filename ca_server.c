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
};

// cert is your X509* (returned from generate_self_signed_cert)
// path is a C string, e.g. "./mycert.pem"
int write_cert_pem(const char *path, X509 *cert) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("fopen");
        return 0;
    }
    int ok = PEM_write_X509(f, cert);
    fclose(f);
    return ok;
}

static void build_db_path(const CAConfig *cfg, const char *filename, char *out, size_t outlen) {
    snprintf(out, outlen, "%s/%s", cfg->db_dir, filename);
}

static CA_STATUS generate_self_signed_cert(CADaemon *ca, X509 **cert);

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
    int key_size = 3072;
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
    key_size_num = CFNumberCreate(NULL, kCFNumberIntType, &key_size);
    REQUIRE_ACTION(key_size_num != NULL, return CA_ERR_MEMORY;);

    label = CFStringCreateWithCString(NULL, ca->cfg->ca_label, kCFStringEncodingUTF8);
    EXIT_IF(label == NULL, status, CA_ERR_MEMORY, "Failed to CFStringCreateWithCString");

    // Private key attributes
    priv_attrs = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionaryAddValue(priv_attrs, kSecAttrIsPermanent, kCFBooleanTrue);

    // Public attributes
    attributes = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, key_size_num);
    //CFDictionaryAddValue(attributes, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
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
CA_STATUS generate_self_signed_cert(CADaemon *ca, X509 **cert)
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
    if (!X509_set1_signature_algo(crt, sig_alg)) {
        DEBUG_LOG("Failure setting signature alg");
        // TODO: handle error
    }

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
        if (status == CA_OK)
        {
            if (!write_cert_pem("ca.cert.pem", ca->ca_cert))
            {
                DEBUG_LOG("Failed to write PEM");
            }
        }
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

    // Setup the config
    ca->cfg = cfg;

    status = lazy_get_keypair(ca);
    REQUIRE_ACTION(status == CA_OK, return CA_ERR_INTERNAL;);

    *out = ca;

    return CA_OK;
}

