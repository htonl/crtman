/*
 * Copyright (c) 2026 NORSEC
 * SPDX-License-Identifier: MIT
 *
 * xpc_shim.c - Provides the Objective-C block literal used for the XPC
 * connection event handler. Rust cannot construct ObjC blocks, so this tiny
 * shim exposes the block pointer for the Rust FFI layer.
 *
 * The CLI only uses synchronous XPC messaging and never needs to react to
 * asynchronous connection events, so the block is a no-op.
 */

#include <xpc/xpc.h>

void *norsec_xpc_noop_event_handler(void)
{
    return (void *)^(xpc_object_t event) {
        (void)event;
    };
}
