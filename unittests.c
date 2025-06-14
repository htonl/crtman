/*
 * Copyright (c) 2025 Luke, lcesarz@pm.me
 * SPDX-License-Identifier: MIT
 *
 * unittests.c - Crtman unittest driver program
 */
#include "handle_request.h"
#include "ca_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utils.h>
#include <limits.h>
#include <assert.h>

#define BUNDLE_ID "com.lctech.crtman"

/*
 * Test key generated via
 * openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test.key.pem
 *
 * Shouldn't need the private key, just saving it in case we ever need it.
 *
static const char *kTestPrivateKeyPem =
    "-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDshu96ifrMtrcb\n"
"qryZ+5pyvzjzUigHM2fs5QD5WEQURpsnU1bKzZESJbbVQm8Hcareh6eYWW6M9kPY\n"
"DjGMaDLRXWGB2Sdk13b3DgEAVr77Hmf66i5AzEkds/tHc7Q/hOJ8gg9Qee6EV/FI\n"
"WnXPG6k3WG/6OkvOoeO93dNQM+T4I+gwvNu+XOmPBTZmM0EAVc2956cuCgXYwjd2\n"
"ggf1PFPwTGQw4cRoW6oeIWYy6lfobrOusuILCEY2LLaeF+s6Lb6qKwTNU4YoIIRF\n"
"zAC9wAGlUuWR6NF419vQ3CzwCT0rROBzCzRm2gG1ySXVV9NO0+S+/fYkrBNdRXvY\n"
"jxVydrW5AgMBAAECggEABe6dw6QBmfAciDbFrihPnQB2FtwroX/vjlMcAs+XktlG\n"
"e5EChJRCnC2SoqdHjkHn4tbiJCxcsm+xZJIj5KfvBliM4SsnascLS8ead34KzNTc\n"
"D2tKJ66NSDptsJgSoDkz+PgbbDhH/CJnLG+1tAZh6GpxEdnecYXr5qTRRO9YQcTl\n"
"w7jYq5Nh05N0CDqCp9ZZdQe/jm7BbA+e+tTzkrFjIYTNW4/b+YyT7y39xvD92pIZ\n"
"HSZ2AbxtjZOeYHerZ6wLtvgoX58oWJUYezGxAjQk8mntkF+LqrTlL0ivXpESK/tN\n"
"LItL6bh6rjOGtXJ4eMnsm9Q8yxiuRE2ghsIhoFMQAQKBgQD2pyQpt2UYT68cVCug\n"
"+F+1z8lwuRpnXI2InUspQbLdqoo0KRqiJ3XUtefn/OvbV4OMYJX/KQDGJnO4KdmI\n"
"ChHyJJAW+x6+NG4swngQfoqzn8YIfoClk+NgybsiY9BtvW1dooKHD9Rk+RicKdTy\n"
"akMfCo5nx5GsQ1ZZV7QHSIKOAQKBgQD1fY9/PTZq+oDj3gdiMkW9Rtz3WaGcfS98\n"
"KNAduzoOqXLTnUNxJ6HaA3diV567jpb+gxT4cxFsVRuxwpQRyBoGgp0o77dAitxH\n"
"ygLdhXqxj/qeUFb7GwQtIBG6WXudlMHjtvg57U+VJ7WJJ6rd5KjZ/Zwow1tLLDmp\n"
"Un7lSVwXuQKBgQDyRLHsl8qg2oPxm2tPLSc1eecu5WHd7LbIXVeaKoH54KznFwim\n"
"BYRjbllfMLqqM4dutuAeRLQR7Wr0lYapbNq7sNYm/Hnx8aXWKR2tdd3fGSx242qR\n"
"OHW6d+trmAb+A3YM5ra22wGQPGvD2ALmKSHMt52wqgGX5nxGPTMDhGFYAQKBgC6B\n"
"JbDl6KwlXktMYTux6FIt3WgiG6JoeJldpecr85iZcv4xeXgzGM8S/werL4+6OFJo\n"
"hI14RuGt0bw/7wrbTErVbW420xEv/QDAfQB368E9VC2vbHrPKGBgBdu2XduBNaWs\n"
"oKNgmEXaKuKbmBvG2FHLYEy8jUvVSesQjKdk2URJAoGAfRVNQfjPM2CW/aZ+r/uH\n"
"lD2CJJW1jsUxpvXgAfI641QBSXMpXCsv3/Qn/loAfad9OvfXRf4dDHikdJc5COeu\n"
"tA1NrQRahxbUs8HUv2rq0cWI3ZrOBw/1vqSu0Rte+J3+TnXwvd0+Vhkm06KH8w2C\n"
"J7EFuls+wHDuRBUmisOFjyc=\n"
"-----END PRIVATE KEY-----";
 */

/*
 * Test CSR generated via below command using hardcoded key above
 *
 * openssl req -new \
 *   -key test.key.pem \
 *   -out test.csr.pem \
 *   -subj "/C=US/ST=State/L=City/O=Org/OU=OrgUnit/CN=unittest.example"
 */
static const char *kTestCsrPem =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIICrDCCAZQCAQAwZzELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYD\n"
    "VQQHDARDaXR5MQwwCgYDVQQKDANPcmcxEDAOBgNVBAsMB09yZ1VuaXQxGTAXBgNV\n"
    "BAMMEHVuaXR0ZXN0LmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
    "AoIBAQDshu96ifrMtrcbqryZ+5pyvzjzUigHM2fs5QD5WEQURpsnU1bKzZESJbbV\n"
    "Qm8Hcareh6eYWW6M9kPYDjGMaDLRXWGB2Sdk13b3DgEAVr77Hmf66i5AzEkds/tH\n"
    "c7Q/hOJ8gg9Qee6EV/FIWnXPG6k3WG/6OkvOoeO93dNQM+T4I+gwvNu+XOmPBTZm\n"
    "M0EAVc2956cuCgXYwjd2ggf1PFPwTGQw4cRoW6oeIWYy6lfobrOusuILCEY2LLae\n"
    "F+s6Lb6qKwTNU4YoIIRFzAC9wAGlUuWR6NF419vQ3CzwCT0rROBzCzRm2gG1ySXV\n"
    "V9NO0+S+/fYkrBNdRXvYjxVydrW5AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEA\n"
    "0s1iCowc/nZmkCQ+WD/US2x9upQdJtMsd1yOlejPuhpK67F9QCJ94y6gu76y/hwl\n"
    "pXCJPItMw1Kfr2J5CfoixTDS8/mrOaBqiEd8kQRcvDAmgg0ks4sUO6jdf30P/qRU\n"
    "YP5pio5fJ3eM1K+n26MlMzO/zte4A/LSbN58pVcygWpKyvHLVR4DAA9UqT6+s2EH\n"
    "egvpoIumD808u3DtFKTCaXZGJqANTPt5PynrE0V/M88PczJfL995JDriXiwwcN9G\n"
    "IXbHfuR62ugAorjJxe4oX5cDDBiuILHi8dPLejy9b8uL+5zn3YaI4WAfYDXuY9Nr\n"
    "e96rqeKoMMdpNHD6TpUY9Q==\n"
    "-----END CERTIFICATE REQUEST-----";

CA_STATUS ca_server_tests(CADaemon *ca, const char *db_dir)
{
    CA_STATUS status;
    char *issued_cert_pem = NULL;
    uint32_t issued_cert_pem_length = 0;
    char *serial = NULL;
    uint32_t serial_length = 0;
    char *crl_pem = NULL;
    uint32_t crl_pem_length = 0;
    char issued_path[PATH_MAX];
    int written = 0;
    char *ca_cert_pem= NULL;
    uint32_t ca_cert_pem_length = 0;

    // 3) Get the CA cert and print it
    status = ca_get_ca_cert(ca, &ca_cert_pem, &ca_cert_pem_length);
    EXIT_IF_ERR(status, "ca_get_ca_cert failed: %d\n", status);
    EXIT_IF(strlen(ca_cert_pem) != ca_cert_pem_length, status, CA_ERR_INTERNAL, "ca_cert_pem_length incorrect");

    printf("✅ ca_get_ca_cert: CA certificate: .\n");
    printf("%s\n", ca_cert_pem);

    // 4) Ask the CA to sign a hard-coded cert
    status = ca_issue_cert(ca, kTestCsrPem, 365, "server", &issued_cert_pem, &issued_cert_pem_length, &serial, &serial_length);
    EXIT_IF_ERR(status, "ca_issue_cert failed: %d", status);
    EXIT_IF(strlen(issued_cert_pem) != issued_cert_pem_length, status, CA_ERR_INTERNAL, "issued_cert_pem_length incorrect");
    EXIT_IF(strlen(serial) != serial_length, status, CA_ERR_INTERNAL, "serial_length incorrect api returned: %u, strlen(serial) = %lu", serial_length, strlen(serial));

    printf("✅ ca_issue_cert. \n");
    printf("Issued Certificate (serial %s):\n%s\n", serial, issued_cert_pem);

    // Write the cert to a file to be verified
    snprintf(issued_path, sizeof(issued_path), "%s/%s", db_dir, "issued.cert.pem");

    FILE *f = fopen(issued_path, "w");
    EXIT_IF(f == NULL, status, CA_ERR_INTERNAL, "Failed to open cert path");

    // 4. Write the cert
    written = fprintf(f, "%s", issued_cert_pem);
    EXIT_IF(written == 0, status, CA_ERR_INTERNAL, "Failed to write issued cert to file");

    // 5. Revoke the cert
    status = ca_revoke_cert(ca, serial, 1);
    EXIT_IF_ERR(status, "ca_revoke_cert failed: %d", status);
    printf("✅ ca_revoke_cert \n");

    // 6. Get the CRL list
    status = ca_get_crl(ca, &crl_pem, &crl_pem_length);
    EXIT_IF_ERR(status, "ca_get_crl failed: %d", status);
    EXIT_IF(strlen(crl_pem) != crl_pem_length, status, CA_ERR_INTERNAL, "crl_pem_length incorrect");

    printf("✅ ca_get_crl\n");
    printf("CRL:\n %s\n", crl_pem);

exit:
    FREE_IF_NOT_NULL(ca_cert_pem, free);
    FREE_IF_NOT_NULL(crl_pem, free);
    FREE_IF_NOT_NULL(issued_cert_pem, free);
    FREE_IF_NOT_NULL(serial, free);

    return status;
}

// Enumeration of supported commands. COPY for code cleanliness
typedef enum {
    CMD_GET_CA_CERT,
    CMD_ISSUE_CERT,
    CMD_REVOKE_CERT,
    CMD_GET_CRL,
    CMD_UNKNOWN
} Command;

// JSON Definitions for the requests
const char *kGetCaCert = "{\"cmd\":\"GetCACert\"}";

const char *kRevokeCert = "{\"cmd\":\"RevokeCert\","
                          "\"serial\":\"01\","
                          "\"reason_code\":1"
                          "}";

const char *kGetCRL = "{\"cmd\":\"GetCRL\"}";

// Helper for the handle_request_tests
static CA_STATUS get_test_request_json(Command cmd, char *json_command, uint32_t command_size_max)
{
    CA_STATUS status = CA_OK;

    switch (cmd)
    {
        case CMD_GET_CA_CERT:
            strlcpy(json_command, kGetCaCert, command_size_max);
            break;
        case CMD_ISSUE_CERT:
            snprintf(json_command, command_size_max,
                    "{"
                      "\"cmd\":\"IssueCert\","
                      "\"csr_pem\":\"%s\","
                      "\"valid_days\":365,"
                      "\"profile\":\"server\""
                    "}",
                    kTestCsrPem);
            break;
        case CMD_REVOKE_CERT:
            strlcpy(json_command, kRevokeCert, command_size_max);
            break;
        case CMD_GET_CRL:
            strlcpy(json_command, kGetCRL, command_size_max);
            break;
        default:
            status = CA_ERR_INTERNAL;
    }

    return status;
}

CA_STATUS handle_request_tests(CADaemon *ca)
{
    char request[2048];
    uint32_t max_length = 2048;
    char *response = NULL;
    Command cmd = CMD_GET_CA_CERT;
    CA_STATUS status = CA_OK;

    for (cmd = CMD_GET_CA_CERT; cmd < CMD_UNKNOWN; cmd++)
    {
        status = get_test_request_json(cmd, request, max_length);
        DEBUG_LOG("Sending request JSON:\n%s", request);
        EXIT_IF_ERR(status, "Failed to get request json");

        status = handle_request(ca, request, &response);
        if (status != CA_OK && response != NULL)
        {
            printf("Error response from handle_request: %s\n", response);
        }
        EXIT_IF_ERR(status, "Failed to get response for cmd:%d, status:  %d", cmd, status);

        printf("Response to command:%d\n%s\n", cmd, response);

        free(response);
        response = NULL;
    }

exit:

    return status;
}

int main(int argc, char **argv)
{
    CA_STATUS status = CA_OK;
    CADaemon *ca;
    char *prefs_path = NULL;
    char *app_support_path = NULL;
    FILE *fp = NULL;
    FILE *fs = NULL;

    if (argc < 4)
    {
        printf("Usage: ./unittests <DB_DIR> <CA_LABEL> <VALIDITY>\n");
        return 0;
    }

    /*
     * Tests to check that daemon can create and modify files in the desired dir
     */
    // 1) build_preferences_path
    prefs_path = build_preferences_path(BUNDLE_ID);
    // 2) build_app_support_path
    app_support_path = build_app_support_path(BUNDLE_ID);
    // 3) check that the files are openable
    fp = fopen(prefs_path, "w");
    EXIT_IF(fp == NULL, status, CA_ERR_INTERNAL, "Failed to open cert path");

    fs = fopen(app_support_path, "w");
    EXIT_IF(fs == NULL, status, CA_ERR_INTERNAL, "Failed to open cert path");

    DEBUG_LOG("Preferences path: %s\n", prefs_path);
    DEBUG_LOG("Application Support path: %s\n", app_support_path);

    // 1) Prepare configuration
    CAConfig cfg = {0};
    cfg.db_dir           = argv[1];
    cfg.ca_label         = argv[2];
    cfg.default_validity = (unsigned)atol(argv[3]);
    cfg.provision_key    = true;   // force provisioning on first run

    // 2) Initialize daemon context
    status = ca_init(&cfg, &ca);
    EXIT_IF_ERR(status, "ca_init failed: %d\n", status);

    printf("✅ ca_init: Generated key and CA certificate.\n");

    /*
     * TESTS
     */

    // ca_server.c tests
    status = ca_server_tests(ca, cfg.db_dir);
    assert(status == CA_OK);

    // handle_request.c tests
    status = handle_request_tests(ca);
    assert(status == CA_OK);

    // 7) Shutdown the CA
    ca_shutdown(&ca);
exit:

    if (fp != NULL)
    {
        fclose(fp);
    }
    if (fs != NULL)
    {
        fclose(fs);
    }

    return 0;
}

