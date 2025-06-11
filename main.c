/*
 * Copyright (c) 2025 Luke, lcesarz@pm.me
 * SPDX-License-Identifier: MIT
 *
 * main.c - Crtman daemon main
 */
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
    CA_STATUS st = CA_OK;
    FILE *fp = NULL;
    FILE *fs = NULL;

    prefs_path = build_preferences_path(BUNDLE_ID);
    app_support_path = build_app_support_path(BUNDLE_ID);

    fp = fopen(prefs_path, "w");
    EXIT_IF(fp == NULL, st, CA_ERR_INTERNAL, "Failed to open cert path");

    fs = fopen(app_support_path, "w");
    EXIT_IF(fs == NULL, st, CA_ERR_INTERNAL, "Failed to open cert path");

    DEBUG_LOG("Preferences path: %s\n", prefs_path);
    DEBUG_LOG("Application Support path: %s\n", app_support_path);

    // 1) Prepare configuration
    CAConfig cfg = {0};
    cfg.db_dir           = argv[1];
    cfg.ca_label         = argv[2];
    cfg.default_validity = (unsigned)atol(argv[3]);
    cfg.provision_key    = true;   // force provisioning on first run

    // 2) Initialize daemon context
    st = ca_init(&cfg, &ca);
    if (st != CA_OK)
    {
        fprintf(stderr, "ca_init failed: %d\n", st);
        return 2;
    }
    else
    {
        printf("✅ Generated SEP key and CA certificate.\n");
    }

exit:
    ca_shutdown(&ca);


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

