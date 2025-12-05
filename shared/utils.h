/*
 * Copyright (c) 2025 Luke, lcesarz@pm.me
 * SPDX-License-Identifier: MIT
 *
 * utils.h - Useful macros/helpers for error handling/logging/debugging
 */
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <stdint.h>

/* Some debugging macros */
#if DEBUG

#define LOG(x)        \
    do                \
    {                 \
        printf x;     \
        printf("\n"); \
    } while (0)

#define REQUIRE_ACTION_LOG(...) LOG((__VA_ARGS__))
#define EXIT_IF_ERR_LOG(...) LOG((__VA_ARGS__))
#define EXIT_IF_FAIL_LOG(...) LOG((__VA_ARGS__))
#define DEBUG_LOG(...) LOG((__VA_ARGS__))

#else /* DEBUG */

#define REQUIRE_ACTION_LOG(...)
#define EXIT_IF_ERR_LOG(...)
#define EXIT_IF_FAIL_LOG(...)
#define DEBUG_LOG(...)

#endif /* DEBUG */

#define REQUIRE_ACTION(condition, action)      \
    do                                         \
    {                                          \
        if (!(condition))                      \
        {                                      \
            REQUIRE_ACTION_LOG(#condition);    \
            action                             \
        }                                      \
    } while (0)

#define EXIT_IF_ERR(status, ...)               \
    do                                         \
    {                                          \
        if (0 != status)                       \
        {                                      \
            EXIT_IF_ERR_LOG(__VA_ARGS__);      \
            goto exit;                         \
        }                                      \
    } while (0)

#define EXIT_IF(condition, status, error, ...) \
    do                                         \
    {                                          \
        if (condition)                         \
        {                                      \
            EXIT_IF_FAIL_LOG(__VA_ARGS__);     \
            status = error;                    \
            goto exit;                         \
        }                                      \
    } while (0)

#define FREE_IF_NOT_NULL(p, f) \
    do                     \
    {                      \
        if (p != NULL)     \
        {                  \
            f(p);          \
            p = NULL;      \
        }                  \
    } while (0)

/*
 * @brief Error codes
 */
typedef enum
{
    CA_OK                  =  0,
    CA_ERR_INTERNAL        = 100,
    CA_ERR_BAD_PARAM       = 110,
    CA_ERR_MEMORY          = 120,
    CA_ERR_BAD_CSR         = 200,
    CA_ERR_POLICY          = 210,
    CA_ERR_NOT_FOUND       = 300,
    CA_ERR_ALREADY_REVOKED = 310,
} ca_status_t;

#define CA_STATUS ca_status_t

typedef int status_t;

/*
 * @brief Build the path to the daemon preferences file used for configuration
 *
 * @param [in] bundleID bundle id of the daemon
 */
char *build_preferences_path(const char *bundleID);

/*
 * @brief Build the path to the daemon app support directory
 *
 * @param [in] bundleID bundle id of the daemon
 */
char *build_app_support_path(const char *bundleID);

/*
 * @brief Build the path to the daemon data directory and create it if needed
 *
 * @param [in] bundleID bundle id of the daemon
 * @return heap-allocated path string, or NULL on error. Caller must free().
 */
char *build_data_dir_path(const char *bundleID);

/*
 * Pretty-print a byte buffer in hex with offsets.
 *
 * @param buf     Pointer to the byte buffer.
 * @param length  Number of bytes in the buffer.
 */
void print_bytes(uint8_t *buf, uint32_t length);

#endif /* _UTILS_H_ */
