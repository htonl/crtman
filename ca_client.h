#ifndef CA_CLIENT_H
#define CA_CLIENT_H

#include <stdint.h>
#include <utils.h>  // for CA_STATUS

/// Opaque client handle
typedef struct CAClient CAClient;

/// Initialize the client handle (connect to the CA XPC service)
CAClient *ca_client_init(void);
/// Shutdown and free the client handle
void      ca_client_shutdown(CAClient *client);

/// Fetch the self-signed CA certificate (PEM) from the daemon
/// On success: *pem_out is heap-allocated NUL-terminated buffer, *pem_length its length, return CA_OK
CA_STATUS ca_client_get_ca_cert(CAClient   *client,
                                char      **pem_out,
                                uint32_t   *pem_length);
CA_STATUS ca_client_get_ca_cert_for_identity(CAClient   *client,
                                             const char *identity,
                                             char      **pem_out,
                                             uint32_t   *pem_length);
CA_STATUS ca_client_add_signing_identity(CAClient   *client,
                                         const char *identity,
                                         char      **pem_out,
                                         uint32_t   *pem_length);
CA_STATUS ca_client_add_signing_identity_signed_by(CAClient   *client,
                                         const char *identity,
                                         const char *signed_by,
                                         char      **pem_out,
                                         uint32_t   *pem_length);
CA_STATUS ca_client_list_signing_identities(CAClient *client, char **json_out);

/// Issue a certificate via the daemon
/// On success: *cert_pem_out and *serial_out with their lengths, return CA_OK
CA_STATUS ca_client_issue_cert(CAClient   *client,
                               const char *csr_pem,
                               unsigned    valid_days,
                               const char *profile,
                               char      **cert_pem_out,
                               uint32_t   *cert_pem_length,
                               char      **serial_out,
                               uint32_t   *serial_length);
CA_STATUS ca_client_issue_cert_for_identity(CAClient   *client,
                               const char *identity,
                               const char *csr_pem,
                               unsigned    valid_days,
                               const char *profile,
                               char      **cert_pem_out,
                               uint32_t   *cert_pem_length,
                               char      **serial_out,
                               uint32_t   *serial_length);

/// Revoke a certificate (reason_code from CRLReason)
CA_STATUS ca_client_revoke_cert(CAClient   *client,
                                const char *serial,
                                int         reason_code);
CA_STATUS ca_client_revoke_cert_for_identity(CAClient   *client,
                                const char *identity,
                                const char *serial,
                                int         reason_code);

/// Fetch the current CRL (PEM) from the daemon
CA_STATUS ca_client_get_crl(CAClient   *client,
                            char      **crl_pem_out,
                            uint32_t   *crl_pem_length);
CA_STATUS ca_client_get_crl_for_identity(CAClient   *client,
                            const char *identity,
                            char      **crl_pem_out,
                            uint32_t   *crl_pem_length);

#endif // CA_CLIENT_H
