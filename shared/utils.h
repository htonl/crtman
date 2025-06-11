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

/* Error definitions */
#define STATUS_SUCCESS 0
#define STATUS_BAD_PARAM -1000
#define STATUS_NO_MEM -1001
#define STATUS_INTERNAL_ERR -1002

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
 * Pretty-print a byte buffer in hex with offsets.
 *
 * @param buf     Pointer to the byte buffer.
 * @param length  Number of bytes in the buffer.
 */
void print_bytes(uint8_t *buf, uint32_t length);

#endif /* _UTILS_H_ */
