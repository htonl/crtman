// test.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ca_server.h"
#include <utils.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr,
                "Usage: %s <db_dir> <ca_label> <validity_seconds>\n"
                "Example: %s ./db com.example.myCA 31536000\n",
                argv[0], argv[0]);
        return 1;
    }
    int a;

    EXIT_IF(1 == 1, a, 5, "Testing ExitIf macro");

exit:

    // 1) Prepare configuration
    CAConfig cfg = {0};
    cfg.db_dir           = argv[1];
    cfg.ca_label         = argv[2];
    cfg.default_validity = (unsigned)atol(argv[3]);
    cfg.provision_key    = true;   // force provisioning on first run

    // 2) Initialize daemon context
    CADaemon *ca = NULL;
    CA_STATUS st = ca_init(&cfg, &ca);
    if (st != CA_OK) {
        fprintf(stderr, "ca_init failed: %d\n", st);
        return 2;
    }
    ca_shutdown(&ca);

    printf("✅ Generated SEP key and CA certificate.\n");

    return 0;
}
