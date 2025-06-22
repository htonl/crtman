#include "ca_client.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include <cJSON.h>

// Mach service name must match the daemon's
#define CA_MACH_SERVICE "com.example.myCA.daemon"

struct CAClient
{
    xpc_connection_t conn;
};

// Internal helper: send a JSON request and get JSON response
static CA_STATUS ca_client_send(CAClient *client, cJSON *req_obj, cJSON **resp_obj)
{
    char *req_str = cJSON_PrintUnformatted(req_obj);
    if (!req_str) return CA_ERR_INTERNAL;

    // Build XPC message
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(msg, "request", req_str);

    // Send and wait for reply
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(
        client->conn, msg);

    xpc_release(msg);
    free(req_str);

    if (!reply) return CA_ERR_INTERNAL;

    const char *resp_str = xpc_dictionary_get_string(reply, "response");
    if (!resp_str)
    {
        xpc_release(reply);
        return CA_ERR_INTERNAL;
    }

    // Parse JSON response
    cJSON *root = cJSON_Parse(resp_str);
    xpc_release(reply);
    if (!root)
    {
        return CA_ERR_INTERNAL;
    }

    // Check status
    cJSON *jstatus = cJSON_GetObjectItem(root, "status");
    if (!cJSON_IsString(jstatus) || strcmp(jstatus->valuestring, "OK") != 0)
    {
        // Could extract error_code / error_msg
        cJSON_Delete(root);
        return CA_ERR_INTERNAL;
    }

    *resp_obj = root;
    return CA_OK;
}

CAClient *ca_client_init(void)
{
    CAClient *client = calloc(1, sizeof(*client));
    if (!client)
    {
        return NULL;
    }
    client->conn = xpc_connection_create_mach_service(
        CA_MACH_SERVICE,
        dispatch_get_main_queue(),
        0
    );
    if (!client->conn)
    {
        free(client);
        return NULL;
    }
    xpc_connection_set_event_handler(client->conn, ^(xpc_object_t obj) {
        // No asynchronous events expected for client
    });
    xpc_connection_resume(client->conn);
    return client;
}

void ca_client_shutdown(CAClient *client)
{
    if (!client) return;
    if (client->conn)
    {
        xpc_connection_cancel(client->conn);
        xpc_release(client->conn);
    }
    free(client);
}

CA_STATUS ca_client_get_ca_cert(CAClient *client,
                                char **pem_out,
                                uint32_t *pem_length) {
    if (!client || !pem_out || !pem_length) return CA_ERR_BAD_PARAM;
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "cmd", "GetCACert");

    cJSON *resp = NULL;
    CA_STATUS st = ca_client_send(client, req, &resp);
    cJSON_Delete(req);
    if (st != CA_OK) return st;

    cJSON *jpem = cJSON_GetObjectItem(resp, "ca_cert_pem");
    if (!cJSON_IsString(jpem)) {
        cJSON_Delete(resp);
        return CA_ERR_INTERNAL;
    }
    const char *s = jpem->valuestring;
    uint32_t len = (uint32_t)strlen(s);
    char *buf = malloc(len + 1);
    if (!buf) {
        cJSON_Delete(resp);
        return CA_ERR_INTERNAL;
    }
    memcpy(buf, s, len + 1);
    *pem_out = buf;
    *pem_length = len;
    cJSON_Delete(resp);
    return CA_OK;
}

CA_STATUS ca_client_issue_cert(CAClient *client,
                               const char *csr_pem,
                               unsigned    valid_days,
                               const char *profile,
                               char      **cert_pem_out,
                               uint32_t   *cert_pem_length,
                               char      **serial_out,
                               uint32_t   *serial_length)
{
    if (!client || !csr_pem || !profile || !cert_pem_out || !serial_out)
    {
        return CA_ERR_BAD_PARAM;
    }

    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "cmd", "IssueCert");
    cJSON_AddStringToObject(req, "csr_pem", csr_pem);
    cJSON_AddNumberToObject(req, "valid_days", valid_days);
    cJSON_AddStringToObject(req, "profile", profile);

    cJSON *resp = NULL;
    CA_STATUS st = ca_client_send(client, req, &resp);
    cJSON_Delete(req);
    if (st != CA_OK)
    {
        return st;
    }

    cJSON *jcert = cJSON_GetObjectItem(resp, "cert_pem");
    cJSON *jserial = cJSON_GetObjectItem(resp, "serial");
    if (!cJSON_IsString(jcert) || !cJSON_IsString(jserial))
    {
        cJSON_Delete(resp);
        return CA_ERR_INTERNAL;
    }
    const char *cs = jcert->valuestring;
    const char *ss = jserial->valuestring;
    uint32_t clen = (uint32_t)strlen(cs);
    uint32_t slen = (uint32_t)strlen(ss);

    char *cbuf = malloc(clen + 1);
    char *sbuf = malloc(slen + 1);
    if (!cbuf || !sbuf)
    {
        free(cbuf); free(sbuf);
        cJSON_Delete(resp);
        return CA_ERR_INTERNAL;
    }
    memcpy(cbuf, cs, clen + 1);
    memcpy(sbuf, ss, slen + 1);

    *cert_pem_out = cbuf;
    *cert_pem_length = clen;
    *serial_out = sbuf;
    *serial_length = slen;

    cJSON_Delete(resp);
    return CA_OK;
}

CA_STATUS ca_client_revoke_cert(CAClient *client,
                                const char *serial,
                                int reason_code)
{
    if (!client || !serial)
    {
        return CA_ERR_BAD_PARAM;
    }

    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "cmd", "RevokeCert");
    cJSON_AddStringToObject(req, "serial", serial);
    cJSON_AddNumberToObject(req, "reason_code", reason_code);

    cJSON *resp = NULL;
    CA_STATUS st = ca_client_send(client, req, &resp);
    cJSON_Delete(req);
    if (st == CA_OK)
    {
        cJSON_Delete(resp);
    }
    return st;
}

CA_STATUS ca_client_get_crl(CAClient *client,
                            char **crl_pem_out,
                            uint32_t *crl_pem_length) {
    if (!client || !crl_pem_out || !crl_pem_length)
    {
        return CA_ERR_BAD_PARAM;
    }

    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "cmd", "GetCRL");

    cJSON *resp = NULL;
    CA_STATUS st = ca_client_send(client, req, &resp);
    cJSON_Delete(req);
    if (st != CA_OK)
    {
        return st;
    }

    cJSON *jcrl = cJSON_GetObjectItem(resp, "crl_pem");
    if (!cJSON_IsString(jcrl))
    {
        cJSON_Delete(resp);
        return CA_ERR_INTERNAL;
    }
    const char *cs = jcrl->valuestring;
    uint32_t len = (uint32_t)strlen(cs);
    char *buf = malloc(len + 1);
    if (!buf)
    {
        cJSON_Delete(resp);
        return CA_ERR_INTERNAL;
    }
    memcpy(buf, cs, len + 1);
    *crl_pem_out = buf;
    *crl_pem_length = len;

    cJSON_Delete(resp);
    return CA_OK;
}

