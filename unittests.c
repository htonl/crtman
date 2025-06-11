#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ca_server.h"
#include <utils.h>
#include <limits.h>

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

int main(int argc, char **argv)
{

    char *prefs_path = NULL;
    char *app_support_path = NULL;
    CADaemon *ca = NULL;
    CA_STATUS status = CA_OK;
    FILE *fp = NULL;
    FILE *fs = NULL;
    char *cert_pem = NULL;
    char *serial = NULL;
    char *crl_pem = NULL;
    char issued_path[PATH_MAX];
    int written = 0;
    char *PEM = NULL;

    if (argc < 4)
    {
        printf("Usage: ./unittests <DB_DIR> <CA_LABEL> <VALIDITY>\n");
        return 0;
    }
    /*
     * TEST)
     *  build_preferences_path()
     *  build_app_support_path()
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

    /*
     * TEST)
     *  ca_init()
     *  ca_get_ca_cert()
     *  ca_shutdown()
     */
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

    // 3) Get the CA cert and print it
    status = ca_get_ca_cert(ca, &PEM);
    EXIT_IF_ERR(status, "ca_get_ca_cert failed: %d\n", status);

    printf("✅ ca_get_ca_cert: CA certificate: .\n");
    printf("%s\n", PEM);

    // 4) Ask the CA to sign a hard-coded cert
    status = ca_issue_cert(ca, kTestCsrPem, 365, "server", &cert_pem, &serial);
    EXIT_IF_ERR(status, "ca_issue_cert failed: %d", status);

    printf("✅ ca_issue_cert. \n");
    printf("Issued Certificate (serial %s):\n%s\n", serial, cert_pem);

    // Write the cert to a file to be verified
    snprintf(issued_path, sizeof(issued_path), "%s/%s", cfg.db_dir, "issued.cert.pem");

    FILE *f = fopen(issued_path, "w");
    EXIT_IF(f == NULL, status, CA_ERR_INTERNAL, "Failed to open cert path");

    // 4. Write the cert
    written = fprintf(f, "%s", cert_pem);
    EXIT_IF(written == 0, status, CA_ERR_INTERNAL, "Failed to write issued cert to file");

    // 5. Revoke the cert
    status = ca_revoke_cert(ca, serial, 1);
    EXIT_IF_ERR(status, "ca_revoke_cert failed: %d", status);
    printf("✅ ca_revoke_cert \n");

    // 6. Get the CRL list
    status = ca_get_crl(ca, &crl_pem);
    EXIT_IF_ERR(status, "ca_get_crl failed: %d", status);

    printf("✅ ca_get_crl\n");
    printf("CRL:\n %s\n", crl_pem);

    // 7) Shutdown the CA
    ca_shutdown(&ca);

exit:

    FREE_IF_NOT_NULL(PEM, free);

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

