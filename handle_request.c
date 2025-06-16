#include "handle_request.h"
#include "ca_server.h"
#include <cJSON.h>
#include <stdlib.h>
#include <string.h>

// Enumeration of supported commands
typedef enum {
    CMD_GET_CA_CERT,
    CMD_ISSUE_CERT,
    CMD_REVOKE_CERT,
    CMD_GET_CRL,
    CMD_UNKNOWN
} Command;

// Static helpers
static CA_STATUS handle_get_ca_cert_req(CADaemon *ca, cJSON *req, char **resp);
static CA_STATUS handle_issue_cert_req(CADaemon *ca, cJSON *req, char **resp);
static CA_STATUS handle_revoke_cert_req(CADaemon *ca, cJSON *req, char **resp);
static CA_STATUS handle_get_crl_req(CADaemon *ca, cJSON *req, char **resp);
static Command parse_command(const char *cmd_str);
static char *build_error_json(int error_code, const char *message);

/*
 * handle_request assumes the caller has authenticated the request
 */
CA_STATUS handle_request(CADaemon *ca, const char *request, char **response)
{
    CA_STATUS status = CA_OK;
    REQUIRE_ACTION(request != NULL, return CA_ERR_BAD_PARAM;);
    REQUIRE_ACTION(response != NULL, return CA_ERR_BAD_PARAM;);

    cJSON *root = cJSON_Parse(request);
    if (!root) {
        *response = build_error_json(200, "Invalid JSON");
        return CA_ERR_INTERNAL;
    }
    cJSON *jcmd = cJSON_GetObjectItem(root, "cmd");
    if (!cJSON_IsString(jcmd)) {
        cJSON_Delete(root);
        *response = build_error_json(201, "Missing 'cmd'");
        return CA_ERR_INTERNAL;
    }
    Command cmd = parse_command(jcmd->valuestring);
    switch (cmd) {
        case CMD_GET_CA_CERT:
            status = handle_get_ca_cert_req(ca, root, response);
            break;
        case CMD_ISSUE_CERT:
            status = handle_issue_cert_req(ca, root, response);
            break;
        case CMD_REVOKE_CERT:
            status = handle_revoke_cert_req(ca, root, response);
            break;
        case CMD_GET_CRL:
            status = handle_get_crl_req(ca, root, response);
            break;
        default:
            *response = build_error_json(202, "Unknown command");
            status = CA_ERR_INTERNAL;
            break;
    }
    cJSON_Delete(root);
    return status;
}

/*
 * @brief parse_command helper to parse the command enum
 */
static Command parse_command(const char *cmd_str) {
    if (strcmp(cmd_str, "GetCACert") == 0)    return CMD_GET_CA_CERT;
    if (strcmp(cmd_str, "IssueCert") == 0)    return CMD_ISSUE_CERT;
    if (strcmp(cmd_str, "RevokeCert") == 0)   return CMD_REVOKE_CERT;
    if (strcmp(cmd_str, "GetCRL") == 0)       return CMD_GET_CRL;
    return CMD_UNKNOWN;
}

/*
 * @brief build_error_json helper to handle json error codes
 */
static char *build_error_json(int error_code, const char *message) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "ERROR");
    cJSON_AddNumberToObject(root, "error_code", error_code);
    cJSON_AddStringToObject(root, "error_msg", message);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

/*
 * @brief Handle the GetCACert Request
 *
 * @param [in] request The incoming request for crtman
 * @param [out] response The response to the request
 */
static CA_STATUS handle_get_ca_cert_req(CADaemon *ca, cJSON *req, char **resp)
{
    (void)req;
    char *pem = NULL;
    uint32_t pem_length = 0;
    CA_STATUS status = ca_get_ca_cert(ca, &pem, &pem_length);
    if (status != CA_OK)
    {
        *resp = build_error_json(ERR_CMD_GET_CA_CERT_FAILED, "GetCACert failed");
        return status;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "OK");
    cJSON_AddStringToObject(root, "ca_cert_pem", pem);
    free(pem);
    *resp = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return CA_OK;
}

/*
 * @brief Handle the IssueCert Request
 *
 * @param [in] request The incoming request for crtman
 * @param [out] response The response to the request
 */
static CA_STATUS handle_issue_cert_req(CADaemon *ca, cJSON *req, char **resp)
{
    cJSON *jcsr = cJSON_GetObjectItem(req, "csr_pem");
    cJSON *jvd  = cJSON_GetObjectItem(req, "valid_days");
    cJSON *jprf = cJSON_GetObjectItem(req, "profile");
    if (!cJSON_IsString(jcsr) || !cJSON_IsNumber(jvd) || !cJSON_IsString(jprf)) {
        *resp = build_error_json(ERR_CMD_ISSUE_CERT_MISSING_PARAM, "IssueCert missing parameters");
        return CA_ERR_INTERNAL;
    }
    const char *csr_pem    = jcsr->valuestring;
    unsigned    valid_days = (unsigned)jvd->valueint;
    const char *profile    = jprf->valuestring;

    char *cert_pem = NULL;
    char *serial   = NULL;
    uint32_t cert_pem_length = 0;
    uint32_t serial_length = 0;
    CA_STATUS status = ca_issue_cert(ca, csr_pem, valid_days, profile,
                                  &cert_pem, &cert_pem_length, &serial, &serial_length);
    if (status != CA_OK)
    {
        *resp = build_error_json(ERR_CMD_ISSUE_CERT_FAILED, "IssueCert failed");
        return status;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status",  "OK");
    cJSON_AddStringToObject(root, "cert_pem", cert_pem);
    cJSON_AddStringToObject(root, "serial",   serial);
    free(cert_pem);
    free(serial);
    *resp = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return CA_OK;
}

/*
 * @brief Handle the RevokeCert Request
 *
 * @param [in] request The incoming request for crtman
 * @param [out] response The response to the request
 */
static CA_STATUS handle_revoke_cert_req(CADaemon *ca, cJSON *req, char **resp)
{
    cJSON *jsn = cJSON_GetObjectItem(req, "serial");
    cJSON *jrs = cJSON_GetObjectItem(req, "reason_code");
    if (!cJSON_IsString(jsn) || !cJSON_IsNumber(jrs)) {
        *resp = build_error_json(ERR_CMD_REVOKE_CERT_MISSING_PARAM, "RevokeCert missing parameters");
        return CA_ERR_INTERNAL;
    }
    const char *serial = jsn->valuestring;
    int reason = jrs->valueint;

    CA_STATUS status = ca_revoke_cert(ca, serial, reason);
    if (status != CA_OK)
    {
        *resp = build_error_json(105, "RevokeCert failed");
        return status;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "OK");
    *resp = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return CA_OK;
}

/*
 * @brief Handle the GetCRL Request
 *
 * @param [in] request The incoming request for crtman
 * @param [out] response The response to the request
 */
static CA_STATUS handle_get_crl_req(CADaemon *ca, cJSON *req, char **resp)
{
    (void)req;
    char *crl_pem = NULL;
    uint32_t crl_pem_length = 0;
    CA_STATUS status = ca_get_crl(ca, &crl_pem, &crl_pem_length);
    if (status != CA_OK)
    {
        *resp = build_error_json(ERR_CMD_GET_CRL_FAILED, "GetCRL failed");
        return status;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "OK");
    cJSON_AddStringToObject(root, "crl_pem", crl_pem);
    free(crl_pem);
    *resp = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return CA_OK;
}

