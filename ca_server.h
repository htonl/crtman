// ca_server.h

// Opaque CA handle
typedef struct CADaemon CADaemon;

// Configuration for initializing CA
typedef struct
{
    const char *db_dir;           // path to serial, index.txt, crl.pem
    const char *sock_path;        // UNIX socket or TCP listen spec
    const char *ca_label;         // Keychain tag for CA SecKey
    unsigned    default_validity; // seconds
    // TLS cert/key files for socket, if using mTLS or server auth
} CAConfig;

// Error codes
enum
{
    CA_OK                   =  0,
    CA_ERR_INTERNAL        =100,
    CA_ERR_BAD_CSR         =200,
    CA_ERR_POLICY          =210,
    CA_ERR_NOT_FOUND       =300,
    CA_ERR_ALREADY_REVOKED =310,
    // …
};

// Initialize the CA: load/generate CA key & cert, open DB files
int  ca_init(const CAConfig *cfg, CADaemon **out);

// Shutdown and free resources
void ca_shutdown(CADaemon *ca);

// Handlers for each command
int  ca_get_ca_cert(CADaemon *ca, char **pem_out);
int  ca_issue_cert(CADaemon *ca,
                   const char *csr_pem,
                   unsigned    valid_days,
                   const char *profile,
                   char      **cert_pem_out,
                   char      **serial_out);
int  ca_revoke_cert(CADaemon *ca,
                    const char *serial,
                    int          reason_code);
int  ca_get_crl(CADaemon *ca, char **crl_pem_out);

// Internal helpers (you’ll implement)
X509_REQ *ca_parse_csr(const char *csr_pem);
X509     *ca_build_cert(CADaemon *ca, X509_REQ *req,
                        ASN1_INTEGER *serial,
                        unsigned       valid_seconds,
                        const char    *profile);
ASN1_INTEGER *ca_next_serial(CADaemon *ca);

int  ca_record_cert(CADaemon *ca, X509 *cert);
int  ca_record_revocation(CADaemon *ca, const char *serial, int reason);

X509_CRL *ca_build_crl(CADaemon *ca);

