/*
 * Copyright (c) 2025 Luke
 * SPDX-License-Identifier: MIT
 *
 * utils.c - Useful macros/helpers for error handling/logging/debugging
 */
#define _POSIX_C_SOURCE 200809L  // for getpwuid_r
#include <stdio.h>
#include <stdlib.h>     // getenv
#include <stdint.h>
#include <string.h>
#include <unistd.h>     // getuid
#include <pwd.h>        // getpwuid_r
#include <sys/types.h>  // uid_t
#include <sys/stat.h>   // mkdir
#include <limits.h>     // PATH_MAX
#include <errno.h>
#include "utils.h"

/**
 * Return a heap-allocated string containing:
 *   <homeDir>/Library/Preferences/<bundleID>.plist
 *
 * bundleID must be a null-terminated C string (e.g. "com.nordsec.crtman").
 *
 * The caller is responsible for free()ing the returned pointer.
 * On error, returns NULL.
 */
char *build_preferences_path(const char *bundleID)
{
    REQUIRE_ACTION(bundleID != NULL, return NULL;);

    // 1) First try getenv("HOME")
    const char *home = getenv("HOME");
    if (!home || home[0] == '\0')
    {
        // Fallback: look up passwd entry for current UID
        struct passwd pwd;
        struct passwd *result = NULL;
        char *buf = NULL;
        size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);

        if (buflen == (size_t)-1)
        {
            // Pick something reasonable
            buflen = 16384;
        }
        buf = malloc(buflen);
        REQUIRE_ACTION(buf != NULL, return NULL;);

        if (getpwuid_r(getuid(), &pwd, buf, buflen, &result) != 0 || result == NULL)
        {
            free(buf);
            return NULL;
        }

        home = result->pw_dir;
        // We will free buf at the end (though pw_dir points inside buf, so copy)
        // Instead of pointing home to result->pw_dir directly, better copy it:
        home = strdup(result->pw_dir);

        free(buf);

        REQUIRE_ACTION(home != NULL, return NULL;);
    }

    // 2) Compute "<home>/Library/Preferences/<bundleID>.plist"
    //    Reserve PATH_MAX bytes to be safe
    char *path = malloc(PATH_MAX);
    if (!path)
    {
        if (home && home != getenv("HOME"))
        {
            free((void*)home);
        }
        return NULL;
    }
    int n = snprintf(path, PATH_MAX,
                     "%s/Library/Preferences/%s.plist",
                     home, bundleID);
    if (n < 0 || n >= PATH_MAX)
    {
        free(path);
        if (home && home != getenv("HOME"))
        {
            free((void*)home);
        }
        return NULL;
    }

    // Cleanup any strdup’d home
    if (home && home != getenv("HOME"))
    {
        free((void*)home);
    }
    return path;
}

/**
 * Return a heap-allocated string containing:
 *   <homeDir>/Library/Application Support/<bundleID>.plist
 *
 * bundleID must be a null-terminated C string (e.g. "com.nordsec.crtman").
 *
 * The caller is responsible for free()ing the returned pointer.
 * On error, returns NULL.
 */
char *build_app_support_path(const char *bundleID)
{
    REQUIRE_ACTION(bundleID != NULL, return NULL;);

    // 1) First try getenv("HOME")
    const char *home = getenv("HOME");
    if (!home || home[0] == '\0')
    {
        // Fallback: look up passwd entry for current UID
        struct passwd pwd;
        struct passwd *result = NULL;
        char *buf = NULL;
        size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);

        if (buflen == (size_t)-1)
        {
            // Pick something reasonable
            buflen = 16384;
        }
        buf = malloc(buflen);
        REQUIRE_ACTION(buf != NULL, return NULL;);

        if (getpwuid_r(getuid(), &pwd, buf, buflen, &result) != 0 || result == NULL)
        {
            free(buf);
            return NULL;
        }

        home = result->pw_dir;
        // We will free buf at the end (though pw_dir points inside buf, so copy)
        // Instead of pointing home to result->pw_dir directly, better copy it:
        home = strdup(result->pw_dir);

        free(buf);

        REQUIRE_ACTION(home != NULL, return NULL;);
    }

    // 2) Compute "<home>/Library/Application Support/<bundleID>.plist"
    //    Reserve PATH_MAX bytes to be safe
    char *path = malloc(PATH_MAX);
    if (!path)
    {
        if (home && home != getenv("HOME"))
        {
            free((void*)home);
        }
        return NULL;
    }
    int n = snprintf(path, PATH_MAX,
                     "%s/Library/Application Support/%s.plist",
                     home, bundleID);
    if (n < 0 || n >= PATH_MAX)
    {
        free(path);
        if (home && home != getenv("HOME"))
        {
            free((void*)home);
        }
        return NULL;
    }

    // Cleanup any strdup'd home
    if (home && home != getenv("HOME"))
    {
        free((void*)home);
    }
    return path;
}

/**
 * Return a heap-allocated string containing:
 *   <homeDir>/Library/Application Support/<bundleID>/
 *
 * Also creates the directory if it doesn't exist.
 *
 * bundleID must be a null-terminated C string (e.g. "com.nordsec.crtman").
 *
 * The caller is responsible for free()ing the returned pointer.
 * On error, returns NULL.
 */
char *build_data_dir_path(const char *bundleID)
{
    REQUIRE_ACTION(bundleID != NULL, return NULL;);

    // 1) First try getenv("HOME")
    const char *home = getenv("HOME");
    char *home_dup = NULL;

    if (!home || home[0] == '\0')
    {
        // Fallback: look up passwd entry for current UID
        struct passwd pwd;
        struct passwd *result = NULL;
        char *buf = NULL;
        size_t buflen = sysconf(_SC_GETPW_R_SIZE_MAX);

        if (buflen == (size_t)-1)
        {
            buflen = 16384;
        }
        buf = malloc(buflen);
        REQUIRE_ACTION(buf != NULL, return NULL;);

        if (getpwuid_r(getuid(), &pwd, buf, buflen, &result) != 0 || result == NULL)
        {
            free(buf);
            return NULL;
        }

        home_dup = strdup(result->pw_dir);
        free(buf);
        REQUIRE_ACTION(home_dup != NULL, return NULL;);
        home = home_dup;
    }

    // 2) Compute "<home>/Library/Application Support/<bundleID>"
    char *path = malloc(PATH_MAX);
    if (!path)
    {
        free(home_dup);
        return NULL;
    }
    int n = snprintf(path, PATH_MAX,
                     "%s/Library/Application Support/%s",
                     home, bundleID);
    if (n < 0 || n >= PATH_MAX)
    {
        free(path);
        free(home_dup);
        return NULL;
    }

    // 3) Create the directory if it doesn't exist
    if (mkdir(path, 0755) != 0 && errno != EEXIST)
    {
        // Failed to create directory
        free(path);
        free(home_dup);
        return NULL;
    }

    free(home_dup);
    return path;
}

void print_bytes(uint8_t *buf, uint32_t length) {
    // Header
    DEBUG_LOG("Buffer (%u bytes):", length);

    // Print 16 bytes per line with offset
    for (uint32_t offset = 0; offset < length; offset += 16) {
        uint32_t line_len = length - offset;
        if (line_len > 16) line_len = 16;

        // Build the line: "0000: AA BB CC ..."
        char line[16 * 3 + 10] = {0};
        char *p = line;
        p += sprintf(p, "%04X: ", offset);
        for (uint32_t i = 0; i < line_len; ++i) {
            p += sprintf(p, "%02X ", buf[offset + i]);
        }

        DEBUG_LOG("%s", line);
    }
}
