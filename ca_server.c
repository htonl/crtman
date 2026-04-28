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
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <Security/Security.h>
#include <pthread.h>
#include <cJSON.h>
#include <ctype.h>

#define IDENTITIES_MANIFEST "identities.json"
#define DEFAULT_IDENTITY_NAME "default"

typedef struct
{
    char *name;
    char *key_label;
    char *db_dir;
    char *signed_by;
    SecKeyRef ca_pk;
    X509 *ca_cert;
    FILE *serial_fd;
    FILE *index_fd;
    FILE *crl_fd;
    pthread_mutex_t index_lock;
    pthread_mutex_t crl_lock;
} CASigningIdentity;

/*
 * @brief CADaemon object
 */
struct CADaemon
{
    CAConfig cfg;
    char *cfg_db_dir;
    char *cfg_ca_label;
    CASigningIdentity *identities;
    size_t identity_count;
    size_t identity_capacity;
    size_t default_identity;
    CADaemonState  state;
};

/*
 * FWD declaration of all static helpers
 */
static CA_STATUS generate_identity_cert(CADaemon *ca, CASigningIdentity *id, CASigningIdentity *issuer, X509 **cert);
static void build_identity_path(const CASigningIdentity *id, const char *filename, char *out, size_t outlen);
static void build_root_path(CADaemon *ca, const char *filename, char *out, size_t outlen);
static void ca_lock_index_file(CASigningIdentity *id);
static void ca_unlock_index_file(CASigningIdentity *id);
static void ca_lock_crl_file(CASigningIdentity *id);
static void ca_unlock_crl_file(CASigningIdentity *id);
static ASN1_INTEGER *ca_next_serial(CASigningIdentity *id);
static CA_STATUS ca_record_cert(CASigningIdentity *id, X509 *cert);
static CA_STATUS ca_generate_keypair(CADaemon *ca, CASigningIdentity *id, CASigningIdentity *issuer);
static CA_STATUS lazy_get_keypair(CADaemon *ca, CASigningIdentity *id, bool provision_key);
static X509_CRL *ca_build_crl_from_index(CASigningIdentity *id);
static CA_STATUS ca_build_crl_for_id(CASigningIdentity *id, char **crl_pem_out, uint32_t *crl_pem_length);
static CA_STATUS ca_load_or_create_identities(CADaemon *ca, bool provision_default);
static CA_STATUS ca_open_identity_files(CASigningIdentity *id);
static CA_STATUS ca_persist_identities(CADaemon *ca);
static CASigningIdentity *ca_find_identity(CADaemon *ca, const char *identity);
static CASigningIdentity *ca_default_identity(CADaemon *ca);
static CA_STATUS ca_add_identity_record(CADaemon *ca, const char *name, const char *key_label, const char *db_dir, const char *signed_by, CASigningIdentity **out);
static char *identity_db_dir(CADaemon *ca, const char *name);
static char *identity_key_label(CADaemon *ca, const char *name);
static bool identity_name_is_valid(const char *name);
static CA_STATUS ca_add_ca_extensions(X509 *cert);
static void ca_delete_keychain_key(const char *key_label);

/*
 * Public API implementation
 */
CA_STATUS ca_init(const CAConfig *cfg, CADaemon **out)
{
    CA_STATUS status = CA_OK;

    REQUIRE_ACTION(cfg != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(out != NULL, return CA_ERR_BAD_PARAM;);

    CADaemon *ca = malloc(sizeof(struct CADaemon));
    REQUIRE_ACTION(ca != NULL, return CA_ERR_MEMORY;);

    ca->state = STARTING;
    ca->identities = NULL;
    ca->identity_count = 0;
    ca->identity_capacity = 0;
    ca->default_identity = 0;

    // 0) Setup the config
    ca->cfg = *cfg;
    ca->cfg_db_dir = strdup(cfg->db_dir);
    ca->cfg_ca_label = strdup(cfg->ca_label);
    EXIT_IF(ca->cfg_db_dir == NULL || ca->cfg_ca_label == NULL, status, CA_ERR_MEMORY, "Failed to copy config");
    ca->cfg.db_dir = ca->cfg_db_dir;
    ca->cfg.ca_label = ca->cfg_ca_label;

    mkdir(ca->cfg.db_dir, 0700);

    status = ca_load_or_create_identities(ca, cfg->provision_key);
    EXIT_IF_ERR(status, "Failed to load identities");

    ca->state = RUNNING;
    *out = ca;

exit:
    if (status != CA_OK && ca)
    {
        ca_shutdown(&ca);
    }

    return status;
}

static CASigningIdentity *ca_default_identity(CADaemon *ca)
{
    REQUIRE_ACTION(ca != NULL, return NULL;);
    REQUIRE_ACTION(ca->identity_count > 0, return NULL;);
    return &ca->identities[ca->default_identity];
}

static CASigningIdentity *ca_find_identity(CADaemon *ca, const char *identity)
{
    REQUIRE_ACTION(ca != NULL, return NULL;);

    if (identity == NULL || identity[0] == '\0')
    {
        return ca_default_identity(ca);
    }

    for (size_t i = 0; i < ca->identity_count; i++)
    {
        if (strcmp(ca->identities[i].name, identity) == 0)
        {
            return &ca->identities[i];
        }
    }

    return NULL;
}

static CA_STATUS ca_add_identity_record(CADaemon *ca, const char *name, const char *key_label, const char *db_dir, const char *signed_by, CASigningIdentity **out)
{
    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(name != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(key_label != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(db_dir != NULL, return CA_ERR_BAD_PARAM;);

    if (ca->identity_count == ca->identity_capacity)
    {
        size_t new_capacity = ca->identity_capacity == 0 ? 4 : ca->identity_capacity * 2;
        CASigningIdentity *new_items = realloc(ca->identities, new_capacity * sizeof(*new_items));
        REQUIRE_ACTION(new_items != NULL, return CA_ERR_MEMORY;);
        memset(new_items + ca->identity_capacity, 0, (new_capacity - ca->identity_capacity) * sizeof(*new_items));
        ca->identities = new_items;
        ca->identity_capacity = new_capacity;
    }

    CASigningIdentity *id = &ca->identities[ca->identity_count++];
    memset(id, 0, sizeof(*id));
    id->name = strdup(name);
    id->key_label = strdup(key_label);
    id->db_dir = strdup(db_dir);
    id->signed_by = signed_by != NULL ? strdup(signed_by) : NULL;
    if (id->name == NULL || id->key_label == NULL || id->db_dir == NULL || (signed_by != NULL && id->signed_by == NULL))
    {
        FREE_IF_NOT_NULL(id->name, free);
        FREE_IF_NOT_NULL(id->key_label, free);
        FREE_IF_NOT_NULL(id->db_dir, free);
        FREE_IF_NOT_NULL(id->signed_by, free);
        ca->identity_count--;
        return CA_ERR_MEMORY;
    }

    mkdir(id->db_dir, 0700);
    pthread_mutex_init(&id->index_lock, NULL);
    pthread_mutex_init(&id->crl_lock, NULL);

    if (out != NULL)
    {
        *out = id;
    }

    return CA_OK;
}

static bool identity_name_is_valid(const char *name)
{
    if (name == NULL || name[0] == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    {
        return false;
    }

    for (const unsigned char *p = (const unsigned char *)name; *p != '\0'; p++)
    {
        if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == '.'))
        {
            return false;
        }
    }

    return true;
}

static CA_STATUS ca_add_ca_extensions(X509 *cert)
{
    CA_STATUS status = CA_OK;
    BASIC_CONSTRAINTS *bc = NULL;
    ASN1_BIT_STRING *usage = NULL;
    X509_EXTENSION *ext = NULL;

    REQUIRE_ACTION(cert != NULL, return CA_ERR_BAD_PARAM;);

    bc = BASIC_CONSTRAINTS_new();
    EXIT_IF(bc == NULL, status, CA_ERR_MEMORY, "Failed to allocate basic constraints");
    bc->ca = ASN1_BOOLEAN_TRUE;

    ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
    EXIT_IF(ext == NULL, status, CA_ERR_INTERNAL, "Failed to create basic constraints extension");
    EXIT_IF(!X509_add_ext(cert, ext, -1), status, CA_ERR_INTERNAL, "Failed to add basic constraints extension");
    FREE_IF_NOT_NULL(ext, X509_EXTENSION_free);

    usage = ASN1_BIT_STRING_new();
    EXIT_IF(usage == NULL, status, CA_ERR_MEMORY, "Failed to allocate key usage");
    EXIT_IF(!ASN1_BIT_STRING_set_bit(usage, 5, 1), status, CA_ERR_INTERNAL, "Failed to set keyCertSign");
    EXIT_IF(!ASN1_BIT_STRING_set_bit(usage, 6, 1), status, CA_ERR_INTERNAL, "Failed to set cRLSign");

    ext = X509V3_EXT_i2d(NID_key_usage, 1, usage);
    EXIT_IF(ext == NULL, status, CA_ERR_INTERNAL, "Failed to create key usage extension");
    EXIT_IF(!X509_add_ext(cert, ext, -1), status, CA_ERR_INTERNAL, "Failed to add key usage extension");

exit:
    FREE_IF_NOT_NULL(ext, X509_EXTENSION_free);
    FREE_IF_NOT_NULL(usage, ASN1_BIT_STRING_free);
    FREE_IF_NOT_NULL(bc, BASIC_CONSTRAINTS_free);
    return status;
}

static void ca_delete_keychain_key(const char *key_label)
{
    CFStringRef label = NULL;
    CFMutableDictionaryRef query = NULL;

    REQUIRE_ACTION(key_label != NULL, return;);

    label = CFStringCreateWithCString(NULL, key_label, kCFStringEncodingUTF8);
    REQUIRE_ACTION(label != NULL, return;);

    query = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    if (query == NULL)
    {
        CFRelease(label);
        return;
    }

    CFDictionaryAddValue(query, kSecClass, kSecClassKey);
    CFDictionaryAddValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionaryAddValue(query, kSecAttrLabel, label);
    SecItemDelete(query);

    CFRelease(query);
    CFRelease(label);
}

static CA_STATUS ca_open_identity_files(CASigningIdentity *id)
{
    char path[PATH_MAX];

    REQUIRE_ACTION(id != NULL, return CA_ERR_BAD_PARAM;);

    build_identity_path(id, "serial", path, sizeof(path));
    id->serial_fd = fopen(path, "a+");
    REQUIRE_ACTION(id->serial_fd != NULL, return CA_ERR_INTERNAL;);

    build_identity_path(id, "index.txt", path, sizeof(path));
    id->index_fd = fopen(path, "a+");
    REQUIRE_ACTION(id->index_fd != NULL, return CA_ERR_INTERNAL;);

    build_identity_path(id, "crl.pem", path, sizeof(path));
    id->crl_fd = fopen(path, "a+");
    REQUIRE_ACTION(id->crl_fd != NULL, return CA_ERR_INTERNAL;);

    return CA_OK;
}

static char *identity_key_label(CADaemon *ca, const char *name)
{
    size_t len = strlen(ca->cfg.ca_label) + 1 + strlen(name) + 1;
    char *out = malloc(len);
    if (out == NULL)
    {
        return NULL;
    }
    snprintf(out, len, "%s:%s", ca->cfg.ca_label, name);
    return out;
}

static char *identity_db_dir(CADaemon *ca, const char *name)
{
    char base[PATH_MAX];
    build_root_path(ca, "identities", base, sizeof(base));
    mkdir(base, 0700);

    size_t len = strlen(base) + 1 + strlen(name) + 1;
    char *out = malloc(len);
    if (out == NULL)
    {
        return NULL;
    }
    snprintf(out, len, "%s/%s", base, name);
    return out;
}

static CA_STATUS ca_persist_identities(CADaemon *ca)
{
    CA_STATUS status = CA_OK;
    char path[PATH_MAX];
    FILE *f = NULL;
    cJSON *root = NULL;
    cJSON *items = NULL;
    char *json = NULL;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);

    root = cJSON_CreateObject();
    EXIT_IF(root == NULL, status, CA_ERR_MEMORY, "Failed to create manifest");
    cJSON_AddStringToObject(root, "version", "1");
    items = cJSON_AddArrayToObject(root, "identities");
    EXIT_IF(items == NULL, status, CA_ERR_MEMORY, "Failed to create identity array");

    for (size_t i = 0; i < ca->identity_count; i++)
    {
        CASigningIdentity *id = &ca->identities[i];
        cJSON *obj = cJSON_CreateObject();
        EXIT_IF(obj == NULL, status, CA_ERR_MEMORY, "Failed to create identity object");
        cJSON_AddStringToObject(obj, "name", id->name);
        cJSON_AddStringToObject(obj, "key_label", id->key_label);
        cJSON_AddStringToObject(obj, "db_dir", id->db_dir);
        if (id->signed_by != NULL)
        {
            cJSON_AddStringToObject(obj, "signed_by", id->signed_by);
        }
        cJSON_AddBoolToObject(obj, "default", i == ca->default_identity);
        cJSON_AddItemToArray(items, obj);
    }

    json = cJSON_Print(root);
    EXIT_IF(json == NULL, status, CA_ERR_MEMORY, "Failed to print manifest");

    build_root_path(ca, IDENTITIES_MANIFEST, path, sizeof(path));
    f = fopen(path, "w");
    EXIT_IF(f == NULL, status, CA_ERR_INTERNAL, "Failed to open identity manifest");
    EXIT_IF(fputs(json, f) < 0, status, CA_ERR_INTERNAL, "Failed to write identity manifest");
    fflush(f);
    fsync(fileno(f));

exit:
    FREE_IF_NOT_NULL(f, fclose);
    FREE_IF_NOT_NULL(json, free);
    FREE_IF_NOT_NULL(root, cJSON_Delete);
    return status;
}

static char *read_text_file(const char *path)
{
    FILE *f = fopen(path, "r");
    long len = 0;
    char *buf = NULL;

    if (f == NULL)
    {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return NULL;
    }
    len = ftell(f);
    if (len < 0)
    {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = malloc((size_t)len + 1);
    if (buf == NULL)
    {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len)
    {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[len] = '\0';
    fclose(f);
    return buf;
}

static CA_STATUS ca_load_or_create_identities(CADaemon *ca, bool provision_default)
{
    CA_STATUS status = CA_OK;
    char manifest_path[PATH_MAX];
    char *json = NULL;
    cJSON *root = NULL;
    cJSON *items = NULL;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);

    build_root_path(ca, IDENTITIES_MANIFEST, manifest_path, sizeof(manifest_path));
    json = read_text_file(manifest_path);

    if (json != NULL)
    {
        root = cJSON_Parse(json);
        EXIT_IF(root == NULL, status, CA_ERR_INTERNAL, "Failed to parse identity manifest");
        items = cJSON_GetObjectItem(root, "identities");
        EXIT_IF(!cJSON_IsArray(items), status, CA_ERR_INTERNAL, "Identity manifest has no array");

        cJSON *item = NULL;
        cJSON_ArrayForEach(item, items)
        {
            cJSON *jname = cJSON_GetObjectItem(item, "name");
            cJSON *jkey = cJSON_GetObjectItem(item, "key_label");
            cJSON *jdir = cJSON_GetObjectItem(item, "db_dir");
            cJSON *jsigned_by = cJSON_GetObjectItem(item, "signed_by");
            cJSON *jdefault = cJSON_GetObjectItem(item, "default");
            CASigningIdentity *id = NULL;
            const char *signed_by = cJSON_IsString(jsigned_by) ? jsigned_by->valuestring : NULL;

            EXIT_IF(!cJSON_IsString(jname) || !cJSON_IsString(jkey) || !cJSON_IsString(jdir), status, CA_ERR_INTERNAL, "Bad identity manifest item");
            status = ca_add_identity_record(ca, jname->valuestring, jkey->valuestring, jdir->valuestring, signed_by, &id);
            EXIT_IF_ERR(status, "Failed to add manifest identity");
            if (cJSON_IsTrue(jdefault))
            {
                ca->default_identity = ca->identity_count - 1;
            }
            status = lazy_get_keypair(ca, id, false);
            EXIT_IF_ERR(status, "Failed to load identity keypair");
            status = ca_open_identity_files(id);
            EXIT_IF_ERR(status, "Failed to open identity files");
        }
    }

    if (ca->identity_count == 0)
    {
        CASigningIdentity *id = NULL;
        char cert_path[PATH_MAX];
        bool provision_default_identity = provision_default;

        status = ca_add_identity_record(ca, DEFAULT_IDENTITY_NAME, ca->cfg.ca_label, ca->cfg.db_dir, NULL, &id);
        EXIT_IF_ERR(status, "Failed to create default identity");

        build_identity_path(id, "ca.cert.pem", cert_path, sizeof(cert_path));
        if (access(cert_path, F_OK) == 0)
        {
            provision_default_identity = false;
        }

        status = lazy_get_keypair(ca, id, provision_default_identity);
        EXIT_IF_ERR(status, "Failed to initialize default keypair");
        status = ca_open_identity_files(id);
        EXIT_IF_ERR(status, "Failed to open default identity files");
        status = ca_persist_identities(ca);
        EXIT_IF_ERR(status, "Failed to persist default identity");
    }

exit:
    FREE_IF_NOT_NULL(root, cJSON_Delete);
    FREE_IF_NOT_NULL(json, free);
    return status;
}

void ca_shutdown(CADaemon **ca)
{
    CADaemon *local = *ca;

    REQUIRE_ACTION(ca != NULL, return ;);
    REQUIRE_ACTION(local!= NULL, return ;);

    local->state = STOPPING;

    for (size_t i = 0; i < local->identity_count; i++)
    {
        CASigningIdentity *id = &local->identities[i];
        FREE_IF_NOT_NULL(id->ca_cert, X509_free);
        FREE_IF_NOT_NULL(id->serial_fd, fclose);
        FREE_IF_NOT_NULL(id->index_fd, fclose);
        FREE_IF_NOT_NULL(id->crl_fd, fclose);
        pthread_mutex_destroy(&id->index_lock);
        pthread_mutex_destroy(&id->crl_lock);
        if (id->ca_pk != NULL)
        {
            ca_delete_keychain_key(id->key_label);
        }
        FREE_IF_NOT_NULL(id->ca_pk, CFRelease);
        FREE_IF_NOT_NULL(id->name, free);
        FREE_IF_NOT_NULL(id->key_label, free);
        FREE_IF_NOT_NULL(id->db_dir, free);
    }

    FREE_IF_NOT_NULL(local->identities, free);
    FREE_IF_NOT_NULL(local->cfg_db_dir, free);
    FREE_IF_NOT_NULL(local->cfg_ca_label, free);

    FREE_IF_NOT_NULL(local, free);
}

CA_STATUS ca_get_ca_cert(CADaemon *ca, char **pem_out, uint32_t *pem_length)
{
    return ca_get_ca_cert_for_identity(ca, NULL, pem_out, pem_length);
}

CA_STATUS ca_get_ca_cert_for_identity(CADaemon *ca,
                                      const char *identity,
                                      char **pem_out,
                                      uint32_t *pem_length)
{
    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;
    char *buf = NULL;
    int res = 0;
    CA_STATUS status = CA_OK;
    CASigningIdentity *id = NULL;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(pem_out != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(pem_length != NULL, return CA_ERR_BAD_PARAM;);

    id = ca_find_identity(ca, identity);
    REQUIRE_ACTION(id != NULL, return CA_ERR_NOT_FOUND;);

    bio = BIO_new(BIO_s_mem());
    REQUIRE_ACTION(bio != NULL, return CA_ERR_MEMORY;);

    res = PEM_write_bio_X509(bio, id->ca_cert);
    EXIT_IF(!res, status, CA_ERR_INTERNAL, "Failed to PEM_write_bio_X509");

    BIO_get_mem_ptr(bio, &bptr);
    EXIT_IF(bptr == NULL, status, CA_ERR_INTERNAL, "Failed to get bio pointer");
    EXIT_IF(bptr->length  == 0, status, CA_ERR_INTERNAL, "Failed to get bio pointer");

    buf = malloc(bptr->length + 1);
    EXIT_IF(buf == NULL, status, CA_ERR_MEMORY, "Failed to allocate pem_out buffer");

    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    *pem_out = buf;
    *pem_length = bptr->length;
exit:

    FREE_IF_NOT_NULL(bio, BIO_free);
    if (status != CA_OK)
    {
        FREE_IF_NOT_NULL(buf, free);
    }

    return status;
}

CA_STATUS ca_list_signing_identities(CADaemon *ca, char **json_out)
{
    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(json_out != NULL, return CA_ERR_BAD_PARAM;);

    cJSON *root = cJSON_CreateArray();
    REQUIRE_ACTION(root != NULL, return CA_ERR_MEMORY;);

    for (size_t i = 0; i < ca->identity_count; i++)
    {
        CASigningIdentity *id = &ca->identities[i];
        cJSON *obj = cJSON_CreateObject();
        if (obj == NULL)
        {
            cJSON_Delete(root);
            return CA_ERR_MEMORY;
        }
        cJSON_AddStringToObject(obj, "name", id->name);
        cJSON_AddStringToObject(obj, "key_label", id->key_label);
        cJSON_AddStringToObject(obj, "db_dir", id->db_dir);
        if (id->signed_by != NULL)
        {
            cJSON_AddStringToObject(obj, "signed_by", id->signed_by);
        }
        cJSON_AddBoolToObject(obj, "default", i == ca->default_identity);
        cJSON_AddItemToArray(root, obj);
    }

    *json_out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return *json_out ? CA_OK : CA_ERR_MEMORY;
}

CA_STATUS ca_add_signing_identity(CADaemon *ca,
                                  const char *identity,
                                  char **ca_cert_pem_out,
                                  uint32_t *ca_cert_pem_length)
{
    return ca_add_signing_identity_signed_by(ca, identity, NULL, ca_cert_pem_out, ca_cert_pem_length);
}

CA_STATUS ca_add_signing_identity_signed_by(CADaemon *ca,
                                  const char *identity,
                                  const char *signed_by,
                                  char **ca_cert_pem_out,
                                  uint32_t *ca_cert_pem_length)
{
    CA_STATUS status = CA_OK;
    CASigningIdentity *id = NULL;
    CASigningIdentity *issuer = NULL;
    size_t issuer_index = 0;
    char *key_label = NULL;
    char *db_dir = NULL;
    bool added = false;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(identity != NULL && identity[0] != '\0', return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(identity_name_is_valid(identity), return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(signed_by == NULL || identity_name_is_valid(signed_by), return CA_ERR_BAD_PARAM;);

    if (ca_find_identity(ca, identity) != NULL)
    {
        return CA_ERR_POLICY;
    }

    if (signed_by != NULL)
    {
        issuer = ca_find_identity(ca, signed_by);
        REQUIRE_ACTION(issuer != NULL, return CA_ERR_NOT_FOUND;);
        issuer_index = (size_t)(issuer - ca->identities);
    }

    key_label = identity_key_label(ca, identity);
    db_dir = identity_db_dir(ca, identity);
    EXIT_IF(key_label == NULL || db_dir == NULL, status, CA_ERR_MEMORY, "Failed to build identity paths");

    status = ca_add_identity_record(ca, identity, key_label, db_dir, signed_by, &id);
    EXIT_IF_ERR(status, "Failed to add identity record");
    added = true;

    if (signed_by != NULL)
    {
        issuer = &ca->identities[issuer_index];
    }

    status = ca_generate_keypair(ca, id, issuer);
    EXIT_IF_ERR(status, "Failed to generate identity keypair");

    status = ca_open_identity_files(id);
    EXIT_IF_ERR(status, "Failed to open identity files");

    status = ca_persist_identities(ca);
    EXIT_IF_ERR(status, "Failed to persist identity manifest");

    if (ca_cert_pem_out != NULL)
    {
        status = ca_get_ca_cert_for_identity(ca, identity, ca_cert_pem_out, ca_cert_pem_length);
        EXIT_IF_ERR(status, "Failed to export identity cert");
    }

exit:
    if (status != CA_OK && added && id != NULL && ca->identity_count > 0)
    {
        FREE_IF_NOT_NULL(id->ca_cert, X509_free);
        FREE_IF_NOT_NULL(id->serial_fd, fclose);
        FREE_IF_NOT_NULL(id->index_fd, fclose);
        FREE_IF_NOT_NULL(id->crl_fd, fclose);
        pthread_mutex_destroy(&id->index_lock);
        pthread_mutex_destroy(&id->crl_lock);
        FREE_IF_NOT_NULL(id->ca_pk, CFRelease);
        FREE_IF_NOT_NULL(id->name, free);
        FREE_IF_NOT_NULL(id->key_label, free);
        FREE_IF_NOT_NULL(id->db_dir, free);
        FREE_IF_NOT_NULL(id->signed_by, free);
        memset(id, 0, sizeof(*id));
        ca->identity_count--;
    }
    FREE_IF_NOT_NULL(key_label, free);
    FREE_IF_NOT_NULL(db_dir, free);
    return status;
}

CA_STATUS ca_issue_cert(CADaemon *ca,
                    const char *csr_pem,
                    unsigned    valid_days,
                    const char *profile,
                    char      **cert_pem_out,
                    uint32_t   *cert_pem_length,
                    char      **serial_out,
                    uint32_t   *serial_length)
{
    return ca_issue_cert_for_identity(ca, NULL, csr_pem, valid_days, profile,
                                      cert_pem_out, cert_pem_length,
                                      serial_out, serial_length);
}

CA_STATUS ca_issue_cert_for_identity(CADaemon *ca,
                    const char *identity,
                    const char *csr_pem,
                    unsigned    valid_days,
                    const char *profile,
                    char      **cert_pem_out,
                    uint32_t   *cert_pem_length,
                    char      **serial_out,
                    uint32_t   *serial_length)
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
    CASigningIdentity *id = NULL;
    // TODO
    (void)profile;

    // 1) Parse the PEM CSR
    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(csr_pem != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(cert_pem_out != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(cert_pem_length != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(serial_out != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(serial_length != NULL, return CA_ERR_BAD_PARAM;);

    id = ca_find_identity(ca, identity);
    REQUIRE_ACTION(id != NULL, return CA_ERR_NOT_FOUND;);

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
    serial_asi = ca_next_serial(id);
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
    issuer_name = X509_NAME_dup(X509_get_subject_name(id->ca_cert));
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

    // 8) signatureAlgorithm for TBSCertificate + outer - ECDSA with SHA-256
    sig_alg = X509_ALGOR_new();
    EXIT_IF(!sig_alg, status, CA_ERR_INTERNAL, "Failed to X509_ALGOR_new");

    X509_ALGOR_set0(sig_alg,
                    OBJ_nid2obj(NID_ecdsa_with_SHA256),
                    V_ASN1_UNDEF, NULL);

    ret = X509_set1_signature_algo(new_cert, sig_alg);
    EXIT_IF(!ret, status, CA_ERR_INTERNAL, "Failed to X509_set1_signature_algo");

    // We can free our local sig_alg; it was dup'd internally
    X509_ALGOR_free(sig_alg);
    sig_alg = NULL;

    // 9) DER-encode the TBSCertificate (everything except signatureValue)
    tbs_len = i2d_re_X509_tbs(new_cert, &tbs_der);
    EXIT_IF((tbs_len <= 0 || !tbs_der), status, CA_ERR_INTERNAL, "Failed to i2d_re_X509_tbs");

    // 10) Let SEP/Keychain sign the TBSCertificate DER with ECDSA
    tbs_data = CFDataCreate(NULL, tbs_der, tbs_len);
    EXIT_IF(!tbs_data, status, CA_ERR_INTERNAL, "Failed to CFDataCreate");

    sig_data = SecKeyCreateSignature(id->ca_pk,
                                     kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                     tbs_data,
                                     &cfErr);

    EXIT_IF(!sig_data, status, CA_ERR_INTERNAL, "Failed to SecKeyCreateSignature (ECDSA)");

    sig_bytes = CFDataGetBytePtr(sig_data);
    sig_len   = CFDataGetLength(sig_data);

    // 11) Attach the signatureValue
    ret = X509_set1_signature_value(new_cert, sig_bytes, sig_len);
    EXIT_IF(!ret, status, CA_ERR_INTERNAL, "Failed to X509_set1_signature_value");

    CFRelease(sig_data);
    sig_data = NULL;

    // 12) Append a line to index.txt (issued)
    status = ca_record_cert(id, new_cert);
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
    *cert_pem_length = bptr->length;
    *serial_out = serial_hex;
    *serial_length = strlen(serial_hex);

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

static CA_STATUS ca_revoke_cert_via_file(CASigningIdentity *id, const char *serial, int reason_code)
{
    // Get current UTC time as YYYYMMDDHHMMSSZ
    char datestr[32];
    time_t now = time(NULL);
    bool found_issued = false;
    bool found_revoked = false;
    char line[1024];
    struct tm gm;

    REQUIRE_ACTION(id != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(serial != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(id->index_fd != NULL, return CA_ERR_INTERNAL;);

    // Lock the index file
    ca_lock_index_file(id);

    if (!gmtime_r(&now, &gm)) {
        return CA_ERR_INTERNAL;
    }
    if (strftime(datestr, sizeof(datestr), "%Y%m%d%H%M%SZ", &gm) == 0) {
        return CA_ERR_INTERNAL;
    }

    // 2) Scan index.txt for issuance (V) and existing revocation (R)
    fseek(id->index_fd, 0, SEEK_SET);

    while (fgets(line, sizeof(line), id->index_fd))
    {
        // Only care about V (valid) or R (revoked) lines
        if (line[0] != 'V' && line[0] != 'R') {
            continue;
        }
        // Find the end of the timestamp (Z)
        char *z = strchr(line, 'Z');
        if (!z) continue;

        // Advance past 'Z' and any spaces/tabs/newlines
        char *p = z + 1;
        while (*p == '\t' || *p == ' ' || *p == '\r' || *p == '\n') {
            p++;
        }
        // p now at start of the serial
        char *start = p;
        // Find end of serial
        while (*p && *p != '\t' && *p != ' ' && *p != '\r' && *p != '\n') {
            p++;
        }
        // Temporarily NUL-terminate
        char saved = *p;
        *p = '\0';

        if (line[0] == 'V' && strcmp(start, serial) == 0) {
            found_issued = true;
        } else if (line[0] == 'R' && strcmp(start, serial) == 0) {
            found_revoked = true;
        }

        // Restore
        *p = saved;
        if (found_issued && found_revoked) break;
    }

    if (!found_issued) {
        DEBUG_LOG("RevokeCert: serial %s not found in index", serial);
        ca_unlock_index_file(id);
        return CA_ERR_BAD_PARAM;
    }
    if (found_revoked) {
        DEBUG_LOG("RevokeCert: serial %s already revoked", serial);
        ca_unlock_index_file(id);
        return CA_ERR_BAD_PARAM;
    }

    // Append: R<TAB><date><TAB><reason><TAB><serial>\n
    fseek(id->index_fd, 0, SEEK_END);
    fprintf(id->index_fd, "R\t%s\t%s\t%d\n", datestr, serial, reason_code);
    fflush(id->index_fd);
    fsync(fileno(id->index_fd));

    // Unlock the index file
    ca_unlock_index_file(id);

    return CA_OK;
}

CA_STATUS ca_revoke_cert(CADaemon *ca, const char *serial, int reason_code)
{
    return ca_revoke_cert_for_identity(ca, NULL, serial, reason_code);
}

CA_STATUS ca_revoke_cert_for_identity(CADaemon *ca, const char *identity, const char *serial, int reason_code)
{
    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(serial != NULL, return CA_ERR_BAD_PARAM;);

    CASigningIdentity *id = ca_find_identity(ca, identity);
    REQUIRE_ACTION(id != NULL, return CA_ERR_NOT_FOUND;);
    REQUIRE_ACTION(id->index_fd != NULL, return CA_ERR_INTERNAL;);

    return ca_revoke_cert_via_file(id, serial, reason_code);
}

CA_STATUS ca_get_crl(CADaemon *ca, char **crl_pem_out, uint32_t *crl_length)
{
    return ca_get_crl_for_identity(ca, NULL, crl_pem_out, crl_length);
}

CA_STATUS ca_get_crl_for_identity(CADaemon *ca, const char *identity, char **crl_pem_out, uint32_t *crl_length)
{
    CA_STATUS status = CA_OK;
    char *local_crl_pem = NULL;
    uint32_t local_crl_pem_length = 0;
    CASigningIdentity *id = NULL;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(crl_pem_out != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(crl_length != NULL, return CA_ERR_BAD_PARAM;);

    id = ca_find_identity(ca, identity);
    REQUIRE_ACTION(id != NULL, return CA_ERR_NOT_FOUND;);

    status = ca_build_crl_for_id(id, &local_crl_pem, &local_crl_pem_length);
    EXIT_IF_ERR(status, "Failed to build crl");

    *crl_pem_out = local_crl_pem;
    *crl_length = local_crl_pem_length;

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
static void build_identity_path(const CASigningIdentity *id, const char *filename, char *out, size_t outlen)
{
    snprintf(out, outlen, "%s/%s", id->db_dir, filename);
}

static void build_root_path(CADaemon *ca, const char *filename, char *out, size_t outlen)
{
    snprintf(out, outlen, "%s/%s", ca->cfg.db_dir, filename);
}

static void ca_lock_index_file(CASigningIdentity *id)
{
    REQUIRE_ACTION(id != NULL, return;);

    pthread_mutex_lock(&id->index_lock);
}

static void ca_unlock_index_file(CASigningIdentity *id)
{
    REQUIRE_ACTION(id != NULL, return;);

    pthread_mutex_unlock(&id->index_lock);
}

static void ca_lock_crl_file(CASigningIdentity *id)
{
    REQUIRE_ACTION(id != NULL, return;);

    pthread_mutex_lock(&id->crl_lock);
}

static void ca_unlock_crl_file(CASigningIdentity *id)
{
    REQUIRE_ACTION(id != NULL, return;);

    pthread_mutex_unlock(&id->crl_lock);
}


// Internal helper implementations
static ASN1_INTEGER *ca_next_serial(CASigningIdentity *id)
{
    unsigned long s = 1;

    REQUIRE_ACTION(id != NULL, return NULL;);

    // Grab the index file lock
    ca_lock_index_file(id);

    // Go to the beginning of the file
    fseek(id->serial_fd, 0, SEEK_SET);

    if (fscanf(id->serial_fd, "%lx", &s) != 1)
    {
        fprintf(id->serial_fd, "%lX", s + 1);
    }
    else
    {
        rewind(id->serial_fd);
        fprintf(id->serial_fd, "%lX", s + 1);
    }

    // Flush no matter what
    fflush(id->serial_fd);
    fsync(fileno(id->serial_fd));

    ASN1_INTEGER *asi = ASN1_INTEGER_new();

    if (!asi)
    {
        ca_unlock_index_file(id);
        return NULL;
    }

    ASN1_INTEGER_set(asi, s);

    ca_unlock_index_file(id);

    return asi;
}

static CA_STATUS ca_record_cert(CASigningIdentity *id, X509 *cert)
{
    CA_STATUS status = CA_OK;
    BIGNUM *bn = NULL;
    char *serial_hex = NULL;
    char *subject = NULL;
    char datestr[32];
    time_t now = time(NULL);
    struct tm gm;

    REQUIRE_ACTION(id != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(cert != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(id->index_fd != NULL, return CA_ERR_INTERNAL;);

    ca_lock_index_file(id);

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

    fseek(id->index_fd, 0, SEEK_END);
    fprintf(id->index_fd, "V\t%s\t%s\t%s\n", datestr, serial_hex, subject);
    fflush(id->index_fd);
    fsync(fileno(id->index_fd));
    status = CA_OK;


exit:

    ca_unlock_index_file(id);

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
static CA_STATUS ca_generate_keypair(CADaemon *ca, CASigningIdentity *id, CASigningIdentity *issuer)
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
    REQUIRE_ACTION(id != NULL, return CA_ERR_BAD_PARAM;);
    if (issuer == NULL)
    {
        issuer = id;
    }

    // Build the attr params - EC P-256 for Secure Enclave compatibility
    key_size_num = CFNumberCreate(NULL, kCFNumberIntType, (int[]){256});
    REQUIRE_ACTION(key_size_num != NULL, return CA_ERR_MEMORY;);

    label = CFStringCreateWithCString(NULL, id->key_label, kCFStringEncodingUTF8);
    EXIT_IF(label == NULL, status, CA_ERR_MEMORY, "Failed to CFStringCreateWithCString");

    // Private key attributes - store in Secure Enclave
    priv_attrs = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(priv_attrs, kSecAttrIsPermanent, kCFBooleanTrue);
#ifdef USE_SECURE_ENCLAVE
    CFDictionaryAddValue(priv_attrs, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
#endif

    // Key attributes - EC P-256 (secp256r1)
    attributes = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, key_size_num);
    CFDictionaryAddValue(attributes, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(attributes, kSecAttrLabel, label);
    CFDictionaryAddValue(attributes, kSecPrivateKeyAttrs, priv_attrs);

    // Create the key
    id->ca_pk = SecKeyCreateRandomKey(attributes, &cf_err);
    if (id->ca_pk == NULL && cf_err != NULL) {
        CFStringRef desc = CFErrorCopyDescription(cf_err);
        if (desc) {
            char buf[256];
            CFStringGetCString(desc, buf, sizeof(buf), kCFStringEncodingUTF8);
            DEBUG_LOG("SecKeyCreateRandomKey failed: %s", buf);
            CFRelease(desc);
        }
        CFRelease(cf_err);
    }
    EXIT_IF(id->ca_pk == NULL, status, CA_ERR_INTERNAL, "Failed to generate EC key");

    // 2. Build CA certificate, either self-signed or signed by issuer.
    status = generate_identity_cert(ca, id, issuer, &local_cert);
    EXIT_IF(status != CA_OK, status, CA_ERR_INTERNAL, "Failed to generate identity certificate");

    id->ca_cert = local_cert;

    // 3. Build the path to the cert
    build_identity_path(id, "ca.cert.pem", cert_path, sizeof(cert_path));

    FILE *f = fopen(cert_path, "w");
    EXIT_IF(f == NULL, status, CA_ERR_INTERNAL, "Failed to open cert path");

    // 4. Write the cert
    written = PEM_write_X509(f, id->ca_cert);
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
 * Create an X509 certificate for the CA using its key. If issuer is NULL,
 * the certificate is self-signed.
 */
static CA_STATUS generate_identity_cert(CADaemon *ca, CASigningIdentity *id, CASigningIdentity *issuer, X509 **cert)
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
    EC_KEY *ec_key = NULL;
    EC_GROUP *ec_group = NULL;

    // Check input
    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(id != NULL, return CA_ERR_BAD_PARAM;);
    if (issuer == NULL)
    {
        issuer = id;
    }

    crt = X509_new();
    EXIT_IF(crt == NULL, status, CA_ERR_MEMORY, "Failed to allocate X509");

    X509_set_version(crt, 2);

    // Serial = 1 for self-signed roots; subordinate identities consume the issuer's serial space.
    serial = ASN1_INTEGER_new();
    EXIT_IF(serial == NULL, status, CA_ERR_MEMORY, "Failed to allocate serial int");

    if (issuer == id)
    {
        ASN1_INTEGER_set(serial, 1);
    }
    else
    {
        ASN1_INTEGER_free(serial);
        serial = ca_next_serial(issuer);
        EXIT_IF(serial == NULL, status, CA_ERR_INTERNAL, "Failed to allocate issuer serial");
    }
    X509_set_serialNumber(crt, serial);

    // Validity
    X509_gmtime_adj(X509_get_notBefore(crt), 0);
    X509_gmtime_adj(X509_get_notAfter(crt), ca->cfg.default_validity);

    // Subject = new identity, issuer = signing identity.
    name = X509_NAME_new();
    EXIT_IF(name == NULL, status, CA_ERR_MEMORY, "Failed to allocate X509 name");
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC,
        (unsigned char *)id->name, -1, -1, 0);
    X509_set_subject_name(crt, name);
    if (issuer == id)
    {
        X509_set_issuer_name(crt, name);
    }
    else
    {
        X509_set_issuer_name(crt, X509_get_subject_name(issuer->ca_cert));
    }

    // Public key from SEP/Keychain - EC P-256
    pub_ref = SecKeyCopyPublicKey(id->ca_pk);
    EXIT_IF(pub_ref == NULL, status, CA_ERR_MEMORY, "Failed to get pubref");

    pub_data = SecKeyCopyExternalRepresentation(pub_ref, &cf_err);
    EXIT_IF(pub_data == NULL, status, CA_ERR_INTERNAL, "Failed to copy pub key ref");

    // Security.framework returns EC public key in X9.63 uncompressed format: 04 || x || y
    const unsigned char *p = CFDataGetBytePtr(pub_data);
    size_t len = CFDataGetLength(pub_data);

    // Create EC_KEY with P-256 curve
    ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EXIT_IF(ec_group == NULL, status, CA_ERR_INTERNAL, "Failed to create EC group");

    ec_key = EC_KEY_new();
    EXIT_IF(ec_key == NULL, status, CA_ERR_INTERNAL, "Failed to create EC_KEY");
    EXIT_IF(!EC_KEY_set_group(ec_key, ec_group), status, CA_ERR_INTERNAL, "Failed to set EC group");

    // Parse X9.63 format public key
    EXIT_IF(!o2i_ECPublicKey(&ec_key, &p, len), status, CA_ERR_INTERNAL, "Failed to parse EC public key");

    evp_pub = EVP_PKEY_new();
    EXIT_IF(!EVP_PKEY_assign_EC_KEY(evp_pub, ec_key), status, CA_ERR_INTERNAL, "Failed to assign EC key");
    // EVP_PKEY_assign_EC_KEY takes ownership
    ec_key = NULL;

    int res = X509_set_pubkey(crt, evp_pub);
    EXIT_IF(res == 0, status, CA_ERR_INTERNAL, "Failed to set pub key in crt");

    // X509 now has a copy
    EVP_PKEY_free(evp_pub);
    evp_pub = NULL;

    status = ca_add_ca_extensions(crt);
    EXIT_IF_ERR(status, "Failed to add CA extensions");

    // 2) Create AlgorithmIdentifier for ECDSA with SHA-256
    sig_alg = X509_ALGOR_new();
    X509_ALGOR_set0(sig_alg, OBJ_nid2obj(NID_ecdsa_with_SHA256), V_ASN1_UNDEF, NULL);

    // 3) Inject into both TBSCertificate and outer signatureAlgorithm:
    EXIT_IF(!X509_set1_signature_algo(crt, sig_alg), status, CA_ERR_INTERNAL, "Failed to set signature algorithm in X509.");

    // Sign TBSCertificate
    tbs_len = i2d_re_X509_tbs(crt, &tbs_der);
    EXIT_IF(tbs_len <= 0, status, CA_ERR_INTERNAL, "tbs_len <= 0");
    EXIT_IF(tbs_der == NULL, status, CA_ERR_INTERNAL, "tbs_der is NULL");

    data = CFDataCreate(NULL, tbs_der, tbs_len);
    // Use ECDSA signature algorithm
    sig = SecKeyCreateSignature(issuer->ca_pk,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        data, &cf_err);
    EXIT_IF(sig == NULL, status, CA_ERR_INTERNAL, "Failed to create ECDSA signature on tbs");

    sig_bytes = CFDataGetBytePtr(sig);
    sig_len = (int)CFDataGetLength(sig);

    // 6) Inject the signature bytes:
    EXIT_IF(!X509_set1_signature_value(crt, sig_bytes, sig_len), status, CA_ERR_INTERNAL, "Failed to set signature value");

    if (issuer != id)
    {
        status = ca_record_cert(issuer, crt);
        EXIT_IF_ERR(status, "Failed to record issued identity certificate");
    }

    // 7) Verify the cert can be serialized
    unsigned char *out_der = NULL;
    int out_len = i2d_X509(crt, &out_der);
    EXIT_IF(out_len <= 0, status, CA_ERR_INTERNAL, "Failed to i2d_X509");
    OPENSSL_free(out_der);

    *cert = crt;

exit:

    FREE_IF_NOT_NULL(data, CFRelease);
    FREE_IF_NOT_NULL(sig, CFRelease);
    FREE_IF_NOT_NULL(ec_key, EC_KEY_free);
    FREE_IF_NOT_NULL(ec_group, EC_GROUP_free);
    FREE_IF_NOT_NULL(serial, ASN1_INTEGER_free);
    FREE_IF_NOT_NULL(name, X509_NAME_free);
    FREE_IF_NOT_NULL(tbs_der, OPENSSL_free);
    FREE_IF_NOT_NULL(pub_ref, CFRelease);
    FREE_IF_NOT_NULL(pub_data, CFRelease);
    FREE_IF_NOT_NULL(evp_pub, EVP_PKEY_free);
    FREE_IF_NOT_NULL(sig_alg, X509_ALGOR_free);

    if (status != CA_OK)
    {
        FREE_IF_NOT_NULL(crt, X509_free);
    }

    return status;

}

static CA_STATUS lazy_get_keypair(CADaemon *ca, CASigningIdentity *id, bool provision_key)
{
    CA_STATUS status = CA_OK;
    FILE *cert_file = NULL;

    REQUIRE_ACTION(ca != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(id != NULL, return CA_ERR_BAD_PARAM;);

    if (provision_key)
    {
        status = ca_generate_keypair(ca, id, NULL);
    }
    else
    {
        char cert_path[PATH_MAX];
        CFMutableDictionaryRef query= CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
        CFDictionaryAddValue(query, kSecClass, kSecClassKey);
        CFDictionaryAddValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
        CFStringRef label = CFStringCreateWithCString(NULL, id->key_label, kCFStringEncodingUTF8);
        EXIT_IF(label == NULL, status, CA_ERR_MEMORY, "Failed to create key label");
        CFDictionaryAddValue(query, kSecAttrLabel, label);
        CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);

        CFTypeRef result = NULL;
        OSStatus res = SecItemCopyMatching(query, &result);
        CFRelease(label);
        CFRelease(query);

        if (res == errSecSuccess)
        {
            id->ca_pk = (SecKeyRef)result;
            build_identity_path(id, "ca.cert.pem", cert_path, sizeof(cert_path));
            cert_file = fopen(cert_path, "r");
            EXIT_IF(cert_file == NULL, status, CA_ERR_INTERNAL, "Failed to open persisted CA certificate");
            id->ca_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
            FREE_IF_NOT_NULL(cert_file, fclose);
            EXIT_IF(id->ca_cert == NULL, status, CA_ERR_INTERNAL, "Failed to read persisted CA certificate");
        }
        else
        {
            status = CA_ERR_INTERNAL;
        }
    }

exit:
    FREE_IF_NOT_NULL(cert_file, fclose);
    return status;
}

static X509_CRL *ca_build_crl_from_index(CASigningIdentity *id)
{
    CA_STATUS status = CA_OK;
    ASN1_ENUMERATED *ent = NULL;
    int err = 0;

    REQUIRE_ACTION(id != NULL, return NULL;);
    REQUIRE_ACTION(id->index_fd != NULL, return NULL;);

    X509_CRL *crl = X509_CRL_new();
    REQUIRE_ACTION(crl != NULL, return NULL;);

    // v2 CRL
    REQUIRE_ACTION(X509_CRL_set_version(crl, 1) != 0, goto exit;);

    // Issuer = CA subject
    REQUIRE_ACTION(X509_CRL_set_issuer_name(crl, X509_get_subject_name(id->ca_cert)) != 0, goto exit;);

    // Set lastUpdate = now, nextUpdate = now + 7 days
    X509_gmtime_adj(X509_CRL_get_lastUpdate(crl), 0);
    X509_gmtime_adj(X509_CRL_get_nextUpdate(crl), 7*24*3600);

    char line[1024];

    ca_lock_index_file(id);

    long reset = ftell(id->index_fd);
    EXIT_IF(reset == -1, status, CA_ERR_INTERNAL, "Failed to reset the file");
    EXIT_IF(fseek(id->index_fd, 0, SEEK_SET) != 0, status, CA_ERR_INTERNAL, "Failed to reset the file");

    while (fgets(line, sizeof(line), id->index_fd)) {
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
    EXIT_IF(fseek(id->index_fd, reset, SEEK_SET) != 0, status, CA_ERR_INTERNAL, "Failed to reset file position after reading");

    // TODO: This should be logged to the system not just debug logged
    if (err > 0)
    {
        DEBUG_LOG("Encountered %d errors when parsing index for CRL", err);
    }

exit:
    ca_unlock_index_file(id);
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

static CA_STATUS ca_build_crl_for_id(CASigningIdentity *id, char **crl_pem_out, uint32_t *crl_pem_length)
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

    REQUIRE_ACTION(id != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(id->crl_fd != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(crl_pem_out != NULL, return CA_ERR_BAD_PARAM;);

    // 1) Build CRL object (unsigned)
    crl = ca_build_crl_from_index(id);
    EXIT_IF(crl == NULL, status, CA_ERR_INTERNAL, "Failed ca_build_crl_from_index");

    // 1.5) Set signature algorithm for TBS - ECDSA with SHA-256
    X509_ALGOR *tbs_alg = X509_ALGOR_new();
    X509_ALGOR_set0(tbs_alg, OBJ_nid2obj(NID_ecdsa_with_SHA256), V_ASN1_UNDEF, NULL);

    // Duplicate into the TBSCertList and outer fields:
    X509_CRL_set1_signature_algo(crl, tbs_alg);
    // free the local copy now:
    X509_ALGOR_free(tbs_alg);

    // 2) DER-encode the TBSCertList
    tbs_len = i2d_re_X509_CRL_tbs(crl, &tbs_der);
    EXIT_IF(tbs_len <= 0, status, CA_ERR_INTERNAL, "Failed to i2d_re_X509_crl_tbs len check");
    EXIT_IF(tbs_der == NULL, status, CA_ERR_INTERNAL, "Failed to i2d_re_X509_crl_tbs null check");

    // 3) Sign via Secure Enclave/Keychain with ECDSA
    tbs_data = CFDataCreate(NULL, tbs_der, tbs_len);
    sig_data = SecKeyCreateSignature(id->ca_pk,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        tbs_data, &cfErr);
    EXIT_IF(!sig_data, status, CA_ERR_INTERNAL, "Failed to SecKeyCreateSignature (ECDSA)");

    sig_bytes = CFDataGetBytePtr(sig_data);
    sig_len   = CFDataGetLength(sig_data);

    // 4) Inject signatureAlgorithm + signatureValue - ECDSA with SHA-256
    sig_alg = X509_ALGOR_new();
    EXIT_IF(!sig_alg, status, CA_ERR_INTERNAL, "Failed to allocate x509");

    X509_ALGOR_set0(sig_alg,
        OBJ_nid2obj(NID_ecdsa_with_SHA256),
        V_ASN1_UNDEF, NULL);
    // This duplicates into both tbs and outer fields
    EXIT_IF(!X509_CRL_set1_signature_algo(crl, sig_alg), status, CA_ERR_INTERNAL, "Failed to X509_CRL_set1_signature_algo");
    // And attach the raw signature bytes
    EXIT_IF(!X509_CRL_set1_signature_value(crl, sig_bytes, sig_len), status, CA_ERR_INTERNAL, "Failed to X509_CRL_set1_signature_value");

    // 5) Write signed CRL to disk
    ca_lock_crl_file(id);
    EXIT_IF(!PEM_write_X509_CRL(id->crl_fd, crl), status, CA_ERR_INTERNAL, "Failed to PEM_write_X509_CRL");
    ca_unlock_crl_file(id);
    fflush(id->crl_fd);
    fsync(fileno(id->crl_fd));

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
    *crl_pem_length = bptr->length;

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
