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

#define BUNDLE_ID "com.nordsec.crtman"

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
static const char *kCaTestCsrPem =
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

/*
 * Private key for second Csr test
 *
 * -----BEGIN PRIVATE KEY-----
 *  MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCivfAmA5FcN77A
 *  lQDNhSe8ONym3VaST5osNuMNjQ5WvUG0SqX1B0oarllEVIlQ32U9Ewsb2pM/TaCi
 *  DyvQML4qrGRmd5XXzw5SzAtBMniwRscMfhZoZllzif3GVGNo+ww53ezehlVbSmoU
 *  xaJB77fdNursFn/oo+Je12Mq+aGG0jog1yPY09dkBZ3R3NYoT7RZsTIzrSrUUVWl
 *  AbNMiBDUNmkjYW9PDl61lOxqZg5yAkjh4BU3KfTBmdUvZJ/fWKp6pMsgDvptH2Lp
 *  ep0xmWogD1Ls2JzDgrIB36Hskiu45PGgRJiDgV/dpyHtWfen+fc8M0clDzXIBPec
 *  /D7mMQNvAgMBAAECggEAItIeHJwd0Yvx6hXXnqHTfy/xcligidyzYat6yG76du+2
 *  q8NfH/7nya6tVfP6j43FBRzafyK059INwS8a0khjoBDTyKLkslDQwUF8VP5eGWWD
 *  eHZQCBWCJTkMzg9HV/KDSqxj3rcCc26IJRqmXZJTlmcGO+6Sfq32JRHT26GfAJAK
 *  WAgSbK6HMRGfgfdspw5j5arRjYE8Bi4mBo73e8TvO0sXOSa115810O2zQUDs6vVJ
 *  Jce/XiaujRY6DKyPvHypb+wa6YtaQ/URPfNK8ApoozNOxQrXLh6xkCag9s/s71Rr
 *  N+b8ouATsC/7sE7X+mdAFOBLeAEJxx0Ip0ZR5wzkUQKBgQDQH/O+6EoOW3s3EFLH
 *  ylZDiThvfUG1BMcituTdwjVWpsm99uHpF2tF4LkgzyEnx1m/O39nUHhIDq3YOU6S
 *  K+JEdtB2YapbhBEZgY4HAbkAp8YRAaaTeBvMvRmR4Xw7WbIqrpHUUMVp+ax0PqYD
 *  JYoIkQrgOSyK5Nq7Cdf4PKVo3wKBgQDILXsiCNRGCsfJfB7jl77yt23d3O97Cu8N
 *  ci3r3RJYnHjdFROQuhifn/g1QcqW3sIhll5lAVtIIPdXUrCIDeph842XMba2yLe6
 *  yW5Khsn0EfzRkAe9yXI9E1T4sclirfMryVa+k+ZecKHfYU3xQWBgzhyl09LJ2O+L
 *  8FBHn4RncQKBgHO2YBlzIsFqwU2zCKNF7sIrx7HMzTxshJ7bWtGkiW083At++MlU
 *  mPLH54XDQ2bPYil9Ve9GASnm52bBLdr9BRcVi/9Ve5bYDX3F1wY0QfyISwnnhgqV
 *  i7dAJ7hAyoZg7zrlxfRqV+f8xZH3xusW8vCiW46gmxA5/xZgea/tX/W3AoGBAJT7
 *  hJEoERSwIVGL11F8NtleO57MOFBTKufO+u54cpcQncOtVAp69qiW3pyEgssWr1Vg
 *  HJEAGXftUSjkmg4ojTCpm8/TaDFR4axbDoLZHqVQXeF6WMifjS53nN4bM88Ft932
 *  02CzotjW6yLdwKy2A40I2blxlYg0tNRp3tXvmxOBAoGBALJS9XiEyzdna6OciDYi
 *  uYJD/89c8fkBmG22DoV7rL7YaRM4aRNyfjaDJ9nxXJqO9CxyVQpzwH76kCZngHFC
 *  o6CepfrPixdU/mQhX2ZT9H7yuCJdr+1EUEh+1vZMMeZSwTuxr6aWJReeF2YIoeZK
 *  /UY0ufDv4ioqIfl6jcWULLJZ
 *  -----END PRIVATE KEY-----
 */
static const char *kRequestTestCsrPem =
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIICrDCCAZQCAQAwZzELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYD\n"
    "VQQHDARDaXR5MQwwCgYDVQQKDANPcmcxEDAOBgNVBAsMB09yZ1VuaXQxGTAXBgNV\n"
    "BAMMEHVuaXR0ZXN0LmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
    "AoIBAQCivfAmA5FcN77AlQDNhSe8ONym3VaST5osNuMNjQ5WvUG0SqX1B0oarllE\n"
    "VIlQ32U9Ewsb2pM/TaCiDyvQML4qrGRmd5XXzw5SzAtBMniwRscMfhZoZllzif3G\n"
    "VGNo+ww53ezehlVbSmoUxaJB77fdNursFn/oo+Je12Mq+aGG0jog1yPY09dkBZ3R\n"
    "3NYoT7RZsTIzrSrUUVWlAbNMiBDUNmkjYW9PDl61lOxqZg5yAkjh4BU3KfTBmdUv\n"
    "ZJ/fWKp6pMsgDvptH2Lpep0xmWogD1Ls2JzDgrIB36Hskiu45PGgRJiDgV/dpyHt\n"
    "Wfen+fc8M0clDzXIBPec/D7mMQNvAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEA\n"
    "S5w5qsZTS8p9UK7nlJVdEM2KPOhVzK1gaokuVq23m6BtLDDSxD/UiVPWddunnZ0/\n"
    "/jEXVNhyksI8956hiYCplvGVbRF/UUuzhmBZfNh0+GJImZCGXE8kIb+McJiRevjS\n"
    "6X77I7p/ZNak5GGtZzjDYQuJarZbTK83GiQNI+mQj202pPpUpz/ok7xZlOyYLnsr\n"
    "NgYxpXmoDAb3g/987a/jDCMZoiw5KisTm8844SzuS3H8vSbiXLVW6Ojpg95o+8l/\n"
    "dM1KNY9Q9A4s7YWj1IDQLjejzPgo6bq4gDRDTLXCM6YxoZdt71k9TOcmn3e12d57\n"
    "Xk9GTWtxj4H0Pgx7fXpv3A==\n"
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
    status = ca_issue_cert(ca, kCaTestCsrPem, 365, "server", &issued_cert_pem, &issued_cert_pem_length, &serial, &serial_length);
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
                          "\"serial\":\"02\","
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
                    kRequestTestCsrPem);
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

