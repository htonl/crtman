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

#include <stdio.h>
#include <stdlib.h>
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>
#include "handle_request.h"
#include "ca_server.h"

#define MAX_LINE_LENGTH 1024

// Global CA context
static CADaemon *g_ca = NULL;

// Handle each new client connection
static void handle_client(xpc_connection_t conn) {
    // Set the event handler for messages from this client
    xpc_connection_set_event_handler(conn, ^(xpc_object_t msg) {
        if (xpc_get_type(msg) != XPC_TYPE_DICTIONARY) {
            return;
        }
        const char *request = xpc_dictionary_get_string(msg, "request");
        char *response = NULL;
        // Dispatch to your JSON handler
        handle_request(g_ca, request, &response);

        // Build reply
        xpc_object_t reply = xpc_dictionary_create_reply(msg);
        if (response) {
            xpc_dictionary_set_string(reply, "response", response);
            free(response);
        } else {
            xpc_dictionary_set_string(reply, "response", "{\"status\":\"ERROR\"}");
        }
        xpc_connection_send_message(conn, reply);
        xpc_release(reply);
    });
    xpc_connection_resume(conn);
}

int main(int argc, const char *argv[]) {
    char *prefs_path = NULL;
    char *app_support_path = NULL;
    FILE *fp = NULL;
    FILE *fs = NULL;
    FILE * cfg_file = NULL;
    CAConfig cfg = {0};

    prefs_path = build_preferences_path(BUNDLE_ID);
    app_support_path = build_app_support_path(BUNDLE_ID);

    fp = fopen(prefs_path, "r");

    DEBUG_LOG("Preferences path: %s\n", prefs_path);
    DEBUG_LOG("Application Support path: %s\n", app_support_path);

    // Use App Support path first
    if ((fs = fopen(app_support_path, "r")) != NULL)
    {
       cfg_file = fs;
    }
    // Fallback to preferences path
    else if ((fp = fopen(prefs_path, "r")) != NULL)
    {
       cfg_file = fp;
    }

    if (cfg_file != NULL)
    {
        char db[MAX_LINE_LENGTH];
        if ((fgets(db, MAX_LINE_LENGTH, cfg_file)) != NULL)
        {
            cfg.db_dir = db;
        }

        char label[MAX_LINE_LENGTH];
        if ((fgets(label, MAX_LINE_LENGTH, cfg_file)) != NULL)
        {
            cfg.ca_label = label;
        }

        char validity_str[MAX_LINE_LENGTH];
        char *endptr;
        if ((fgets(validity_str, MAX_LINE_LENGTH, cfg_file)) != NULL)
        {
            cfg.default_validity = strtoul(validity_str, &endptr, 10);
        }

        char provision[MAX_LINE_LENGTH];
        if ((fgets(provision, MAX_LINE_LENGTH, cfg_file)) != NULL)
        {
            if (strncmp(provision, "true", 4) == 0)
            {
                cfg.provision_key = true;
            }
            else
            {
                cfg.provision_key = false;
            }
        }

    }
    // Defaults
    else
    {
        // Default config if no file provided
        cfg.db_dir = "./db";
        cfg.ca_label = BUNDLE_ID;
        cfg.default_validity = 365 * 24 * 3600;
        cfg.provision_key = true;
    }

    // 1) Initialize the CA
    if (ca_init(&cfg, &g_ca) != CA_OK) {
        fprintf(stderr, "Failed to initialize CA\n");
        return 1;
    }

    // 2) Create an XPC listener for your Mach service
    xpc_connection_t listener = xpc_connection_create_mach_service(
        BUNDLE_ID,  // Mach service name
        dispatch_get_main_queue(),
        XPC_CONNECTION_MACH_SERVICE_LISTENER
    );
    if (!listener) {
        fprintf(stderr, "Failed to create XPC listener\n");
        return 1;
    }

    // 3) Accept new connections
    xpc_connection_set_event_handler(listener, ^(xpc_object_t conn) {
        handle_client((xpc_connection_t)conn);
    });
    xpc_connection_resume(listener);

    // 4) Run the dispatch loop
    dispatch_main();

    FREE_IF_NOT_NULL(prefs_path, free);
    FREE_IF_NOT_NULL(app_support_path, free);

    ca_shutdown(&g_ca);
    return 0;
}
/*
int main(int argc, char **argv)
{

    CADaemon *ca = NULL;
    CA_STATUS st = CA_OK;
    FILE *fp = NULL;
    FILE *fs = NULL;


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
*/
