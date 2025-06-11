// ca_server.h
#include <openssl/x509.h>
#include <stdbool.h>

/* 
 * @brief Opaque CADaemon object
 */
typedef struct CADaemon CADaemon;

/*
 * @brief Configuration for initializing CA
 */
typedef struct
{
    const char *db_dir;           // path to serial, index.txt, crl.pem
    const char *sock_path;        // UNIX socket or TCP listen spec
    const char *ca_label;         // Keychain tag for CA SecKey
    unsigned    default_validity; // seconds
    bool        provision_key;    // Provision the private/pubkeys
} CAConfig;

/*
 * @brief Error codes
 */
typedef enum
{
    CA_OK                  =  0,
    CA_ERR_INTERNAL        = 100,
    CA_ERR_BAD_PARAM       = 110,
    CA_ERR_MEMORY          = 120,
    CA_ERR_BAD_CSR         = 200,
    CA_ERR_POLICY          = 210,
    CA_ERR_NOT_FOUND       = 300,
    CA_ERR_ALREADY_REVOKED = 310,
} ca_status_t;

/*
 * @brief State for the daemon
 */
typedef enum
{
    STARTING = 1,
    RUNNING = 1,
    STOPPING = 1,
} CADaemonState;

#define CA_STATUS ca_status_t

/*
 * @brief Initialize the CA: load/generate CA key & cert, open DB files
 * 
 * @param [in]  cfg Configuration for initializing the CA
 * @param [out] out Internally allocated CADaemon 
 */
CA_STATUS ca_init(const CAConfig *cfg, CADaemon **out);

/*
 * @brief Shutdown and free resources
 *
 * @param [in] ca CA object to shutdown and free
 */
void ca_shutdown(CADaemon **ca);

// Handlers for each command

/*
 * @brief Get the CA public certificate
 *
 * @param [in] CADaemon to retrieve the cert from
 * @param [out] Internally allocated cert pem
 */
CA_STATUS ca_get_ca_cert(CADaemon *ca, char **pem_out);

/*
 * @brief Handle CSR request
 *
 * @param [in] cs CADaemon to sign the certificate
 * @param [in] csr_pem the CSR from the client
 * @param [in] valid_days the number of days for the new cert to be valid
 * @param [in] profile The profile of new certificate - currently unused
 * @param [out] cert_pem_out Internally allocated output certificate in pem format
 * @param [out] serial_out Internally allocated serial number of the output cert
 */
CA_STATUS ca_issue_cert(CADaemon *ca,
                   const char *csr_pem,
                   unsigned    valid_days,
                   const char *profile,
                   char      **cert_pem_out,
                   char      **serial_out);

/*
 * @brief Handle revoke request
 *
 * @param [in] ca CADaemon to revoke the certificate for
 * @param [in] serial The serial number of the certificate to revoke
 * @param [in reason_code The reason for revoking the certificate
 */
CA_STATUS ca_revoke_cert(CADaemon *ca,
                    const char *serial,
                    int          reason_code);

/*
 * @brief get the CRL for the CA
 *
 * @param [in] ca CADaemon to retrieve the CRL from
 * @param [out] crl_pem_out the CRL of the CA in pem format
 */
CA_STATUS ca_get_crl(CADaemon *ca, char **crl_pem_out);

