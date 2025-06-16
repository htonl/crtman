/*
 * Copyright (c) 2025 Luke, lcesarz@pm.me
 * SPDX-License-Identifier: MIT
 *
 * handle_request.h - Public API for crtman handling JSON requests 
 */
#ifndef _HANDLE_REQUEST_H_
#define _HANDLE_REQUEST_H_

#include "ca_server.h"
#include <utils.h>

/*
 * A REQUEST is made up of JSON tokens. This makes it easy to transmit from a
 * variety of consumers in a REST format. Responses are also JSON, examples.
 *
 * GetCACert REQUEST
 * {
 *     "cmd": "GetCACert"
 * }
 *
 * GetCACert RESPONSE
 * {
 *     "status": "OK",
 *     "ca_cert_pem": "-----BEGIN CERTIFICATE-----…"
 * }
 * 
 * IssueCert REQUEST
 * {
 *     "cmd":        "IssueCert",
 *     "csr_pem":    "-----BEGIN CERTIFICATE REQUEST-----…",
 *     "valid_days": 365,
 *     "profile":    "server"
 * }
 *
 * IssueCert RESPONSE
 * {
 *     "status": "OK",
 *     "cert_pem":  "-----BEGIN CERTIFICATE-----…",
 *     "serial":    "0x1001"
 * }
 * 
 * RevokeCert REQUEST
 * {
 *     "cmd":         "RevokeCert",
 *     "serial":      "0x1001",
 *     "reason_code": 1
 * }
 *
 * RevokeCert RESPONSE
 * {
 *     "status": "OK"
 * }
 * 
 * GetCRL REQUEST
 * {
 *     "cmd": "GetCRL"
 * }
 *
 * GetCRL RESPONSE
 * { 
 *     "status": "OK",
 *     "crl_pem": "-----BEGIN X509 CRL-----…"
 * }
 *
 */

// Eerror enum
typedef enum {
    ERR_CMD_GET_CA_CERT_FAILED = 101,
    ERR_CMD_ISSUE_CERT_MISSING_PARAM = 102,
    ERR_CMD_ISSUE_CERT_FAILED = 103,
    ERR_CMD_REVOKE_CERT_MISSING_PARAM = 104,
    ERR_CMD_REVOKE_CERT_FAILED = 105,
    ERR_CMD_GET_CRL_FAILED = 105,
} cmd_err_t;

/*
 * @brief Dispatch the incoming requests of the daemon
 *
 * @param [in] request The incoming request for crtman
 * @param [out] response The response to the request
 */
CA_STATUS handle_request(CADaemon *ca, const char *request, char **response);

#endif /* _HANDLE_REQUEST_H_ */

