#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ca_server.h"
#include <utils.h>

#define BUNDLE_ID "com.lctech.crtman"

int main(int argc, char **argv)
{

    char *prefs_path = NULL;
    char *app_support_path = NULL;
    CADaemon *ca = NULL;
    CA_STATUS status = CA_OK;
    FILE *fp = NULL;
    FILE *fs = NULL;

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

    char *PEM;
    status = ca_get_ca_cert(ca, &PEM);
    EXIT_IF_ERR(status, "ca_get_ca_cert failed: %d\n", status);

    printf("✅ ca_get_ca_cert: CA certificate: .\n");
    printf("%s\n", PEM);

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

