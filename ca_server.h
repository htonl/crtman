/*
 * Copyright (c) 2025 Luke, lcesarz@pm.me
 * SPDX-License-Identifier: MIT
 *
 * ca_server.h - Public API for crtman daemon internals
 */
#ifndef _H_CA_SERVER_H_
#define _H_CA_SERVER_H_
#include <utils.h>
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
 * @brief State for the daemon
 */
typedef enum
{
    STARTING = 1,
    RUNNING = 1,
    STOPPING = 1,
} CADaemonState;

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

/*
 * @brief Get the CA public certificate
 *
 * @param [in] CADaemon to retrieve the cert from
 * @param [out] Internally allocated cert pem
 */
CA_STATUS ca_get_ca_cert(CADaemon *ca, char **pem_out, uint32_t *pem_length);

/*
 * @brief Handle CSR request
 *
 * @param [in] cs CADaemon to sign the certificate
 * @param [in] csr_pem the CSR from the client
 * @param [in] valid_days the number of days for the new cert to be valid
 * @param [in] profile The profile of new certificate - currently unused
 * @param [out] cert_pem_out Internally allocated output certificate in pem format
 * @param [out] cert_pem_length Length of allocated output certificate in pem format
 * @param [out] serial_out Internally allocated serial number of the output cert
 * @param [out] serial_length Length of allocated serial number of the output cert
 */
CA_STATUS ca_issue_cert(CADaemon *ca,
                   const char *csr_pem,
                   unsigned    valid_days,
                   const char *profile,
                   char      **cert_pem_out,
                   uint32_t    *cert_pem_length,
                   char      **serial_out,
                   uint32_t    *serial_length);

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
 * @param [out] crl_pem_length the length of the CRL
 */
CA_STATUS ca_get_crl(CADaemon *ca, char **crl_pem_out, uint32_t *crl_pem_length);

#endif /* _H_CA_SERVER_H_ */
