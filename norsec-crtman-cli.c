/*
 * Copyright (c) 2026 NORSEC
 * SPDX-License-Identifier: MIT
 *
 * norsec-crtman-cli.c - Thin CLI wrapper over ca_client XPC API.
 *
 * Usage:
 *   norsec-crtman-cli get-ca-cert
 *       -> writes the CA root cert (PEM) to stdout.
 *
 *   norsec-crtman-cli issue-cert [--valid-days N] [--profile NAME]
 *       -> reads a PKCS#10 CSR (PEM) from stdin,
 *          writes the issued X.509 cert (PEM) to stdout,
 *          writes the cert serial (hex) to stderr.
 *
 *   norsec-crtman-cli get-crl
 *       -> writes the current CRL (PEM) to stdout.
 *
 * Exit codes:
 *   0  success
 *   1  runtime error (XPC connect, server returned error, parse error)
 *   2  bad usage
 *
 * The CLI does no crypto itself — everything is delegated to the
 * crtman daemon via the ca_client XPC facade. Designed to be safe to
 * invoke from a shell pipeline (e.g. provisioning scripts) and from
 * over ssh from the NORSEC host machine.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "ca_client.h"

static int usage(FILE *out)
{
    fprintf(out,
        "usage:\n"
        "  norsec-crtman-cli get-ca-cert\n"
        "  norsec-crtman-cli issue-cert [--valid-days N] [--profile NAME]\n"
        "  norsec-crtman-cli get-crl\n");
    return 2;
}

/* Slurp stdin into a freshly-allocated buffer. Caller frees. Returns
 * NULL on error. *len_out is set to the number of bytes read. The
 * buffer is NUL-terminated so it's safe to pass to PEM parsers. */
static char *read_all_stdin(size_t *len_out)
{
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len + 4096 > cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        ssize_t n = read(STDIN_FILENO, buf + len, cap - len - 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf);
            return NULL;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    buf[len] = '\0';
    *len_out = len;
    return buf;
}

static int cmd_get_ca_cert(void)
{
    CAClient *c = ca_client_init();
    if (!c) { fprintf(stderr, "ca_client_init failed\n"); return 1; }
    char *pem = NULL; uint32_t len = 0;
    CA_STATUS st = ca_client_get_ca_cert(c, &pem, &len);
    if (st != CA_OK) {
        fprintf(stderr, "get-ca-cert failed: status=%d\n", st);
        ca_client_shutdown(c);
        return 1;
    }
    fwrite(pem, 1, len, stdout);
    free(pem);
    ca_client_shutdown(c);
    return 0;
}

static int cmd_issue_cert(unsigned valid_days, const char *profile)
{
    size_t in_len = 0;
    char *csr = read_all_stdin(&in_len);
    if (!csr) { fprintf(stderr, "read stdin failed\n"); return 1; }
    if (in_len == 0) {
        fprintf(stderr, "issue-cert: empty stdin (expected PEM CSR)\n");
        free(csr);
        return 1;
    }
    CAClient *c = ca_client_init();
    if (!c) { fprintf(stderr, "ca_client_init failed\n"); free(csr); return 1; }
    char *cert_pem = NULL; uint32_t cert_len = 0;
    char *serial = NULL;   uint32_t serial_len = 0;
    CA_STATUS st = ca_client_issue_cert(c, csr, valid_days, profile,
                                        &cert_pem, &cert_len,
                                        &serial, &serial_len);
    free(csr);
    if (st != CA_OK) {
        fprintf(stderr, "issue-cert failed: status=%d\n", st);
        ca_client_shutdown(c);
        return 1;
    }
    fwrite(cert_pem, 1, cert_len, stdout);
    fprintf(stderr, "serial=%s\n", serial);
    free(cert_pem);
    free(serial);
    ca_client_shutdown(c);
    return 0;
}

static int cmd_get_crl(void)
{
    CAClient *c = ca_client_init();
    if (!c) { fprintf(stderr, "ca_client_init failed\n"); return 1; }
    char *pem = NULL; uint32_t len = 0;
    CA_STATUS st = ca_client_get_crl(c, &pem, &len);
    if (st != CA_OK) {
        fprintf(stderr, "get-crl failed: status=%d\n", st);
        ca_client_shutdown(c);
        return 1;
    }
    fwrite(pem, 1, len, stdout);
    free(pem);
    ca_client_shutdown(c);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage(stderr);
    const char *cmd = argv[1];

    if (strcmp(cmd, "get-ca-cert") == 0) {
        return cmd_get_ca_cert();
    }
    if (strcmp(cmd, "get-crl") == 0) {
        return cmd_get_crl();
    }
    if (strcmp(cmd, "issue-cert") == 0) {
        unsigned valid_days = 365;
        const char *profile = "server";
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--valid-days") == 0 && i + 1 < argc) {
                valid_days = (unsigned)strtoul(argv[++i], NULL, 10);
            } else if (strcmp(argv[i], "--profile") == 0 && i + 1 < argc) {
                profile = argv[++i];
            } else {
                fprintf(stderr, "unknown arg: %s\n", argv[i]);
                return usage(stderr);
            }
        }
        return cmd_issue_cert(valid_days, profile);
    }
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        usage(stdout);
        return 0;
    }
    return usage(stderr);
}
