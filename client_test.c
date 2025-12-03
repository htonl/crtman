#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "ca_client.h"

int main(void) {
    CAClient *client = ca_client_init();
    if (!client) {
        fprintf(stderr, "Failed to initialize CA client\n");
        return 1;
    }

    // 1) Fetch the CA certificate
    char *ca_pem = NULL;
    uint32_t ca_len = 0;
    if (ca_client_get_ca_cert(client, &ca_pem, &ca_len) == CA_OK) {
        printf("--- CA Certificate (len %u) ---\n%s\n", ca_len, ca_pem);
        free(ca_pem);
    } else {
        fprintf(stderr, "ca_client_get_ca_cert failed\n");
    }

    /*// 2) Issue a certificate (using a placeholder CSR)
    const char *csr_pem =
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIIBWDCB...PLACEHOLDER...IDAQAB\n"
        "-----END CERTIFICATE REQUEST-----\n";
    char *issued_pem = NULL;
    uint32_t issued_len = 0;
    char *serial = NULL;
    uint32_t serial_len = 0;
    if (ca_client_issue_cert(client,
                              csr_pem,
                              365,
                              "server",
                              &issued_pem,
                              &issued_len,
                              &serial,
                              &serial_len) == CA_OK) {
        printf("--- Issued Certificate (len %u) ---\n%s\n", issued_len, issued_pem);
        printf("Serial: %s\n", serial);
        free(issued_pem);
        free(serial);
    } else {
        fprintf(stderr, "ca_client_issue_cert failed\n");
    }

    // 3) Revoke the issued certificate
    if (serial) {
        if (ca_client_revoke_cert(client, serial, 1) == CA_OK) {
            printf("Serial %s revoked (reason 1)\n", serial);
        } else {
            fprintf(stderr, "ca_client_revoke_cert failed\n");
        }
    }

    // 4) Fetch the CRL
    char *crl_pem = NULL;
    uint32_t crl_len = 0;
    if (ca_client_get_crl(client, &crl_pem, &crl_len) == CA_OK) {
        printf("--- CRL (len %u) ---\n%s\n", crl_len, crl_pem);
        free(crl_pem);
    } else {
        fprintf(stderr, "ca_client_get_crl failed\n");
    }*/

    ca_client_shutdown(client);
    return 0;
}
