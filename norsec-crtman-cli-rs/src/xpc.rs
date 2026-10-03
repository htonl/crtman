//! Thin FFI wrapper over Apple's XPC C API for talking to the crtman daemon.
//!
//! The daemon exposes a Mach service named `com.norsec.crtman` that speaks a
//! simple JSON protocol: the client sends an XPC dictionary with a `request`
//! string field (a JSON document) and receives an XPC dictionary back with a
//! `response` string field (a JSON document).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

/// Opaque XPC object handle.
pub type XpcObject = *mut c_void;

#[allow(non_snake_case)]
extern "C" {
    fn xpc_connection_create_mach_service(
        name: *const c_char,
        queue: *mut c_void,
        flags: u64,
    ) -> XpcObject;

    fn xpc_connection_set_event_handler(conn: XpcObject, handler: *mut c_void);
    fn xpc_connection_resume(conn: XpcObject);
    fn xpc_connection_cancel(conn: XpcObject);

    fn xpc_dictionary_create(
        tmpl: XpcObject,
        keys: *const *const c_char,
        values: *const XpcObject,
        count: u64,
    ) -> XpcObject;

    fn xpc_dictionary_set_string(d: XpcObject, key: *const c_char, value: *const c_char);
    fn xpc_dictionary_get_string(d: XpcObject, key: *const c_char) -> *const c_char;

    fn xpc_connection_send_message_with_reply_sync(conn: XpcObject, msg: XpcObject) -> XpcObject;
    fn xpc_release(obj: XpcObject);

    fn dispatch_get_main_queue() -> *mut c_void;
    /// Returns a pointer to a no-op event-handler block (defined in xpc_shim.c).
    fn norsec_xpc_noop_event_handler() -> *mut c_void;
}

const MACH_SERVICE: &str = "com.norsec.crtman";

/// A handle to the crtman daemon over XPC.
pub struct CAClient {
    conn: XpcObject,
}

impl CAClient {
    /// Connect to the `com.norsec.crtman` Mach service.
    pub fn new() -> Result<Self, String> {
        let name = CString::new(MACH_SERVICE).map_err(|_| "NUL byte in service name")?;
        let conn = unsafe {
            xpc_connection_create_mach_service(name.as_ptr(), dispatch_get_main_queue(), 0)
        };
        if conn.is_null() {
            return Err("xpc_connection_create_mach_service failed".into());
        }
        unsafe {
            xpc_connection_set_event_handler(conn, norsec_xpc_noop_event_handler());
            xpc_connection_resume(conn);
        }
        Ok(Self { conn })
    }

    /// Send a JSON request document to the daemon and return the parsed JSON
    /// response document. Errors if the daemon returns a non-OK status.
    pub fn send(&self, request: &serde_json::Value) -> Result<serde_json::Value, String> {
        let req_str = serde_json::to_string(request).map_err(|e| e.to_string())?;
        let req_c = CString::new(req_str).map_err(|_| "NUL byte in request")?;

        let msg = unsafe { xpc_dictionary_create(std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0) };
        if msg.is_null() {
            return Err("failed to allocate XPC message".into());
        }
        unsafe {
            xpc_dictionary_set_string(msg, b"request\0".as_ptr() as *const c_char, req_c.as_ptr());
        }

        let reply = unsafe { xpc_connection_send_message_with_reply_sync(self.conn, msg) };
        unsafe { xpc_release(msg) };

        if reply.is_null() {
            return Err("no reply from daemon (is com.norsec.crtman running?)".into());
        }

        let resp_ptr = unsafe { xpc_dictionary_get_string(reply, b"response\0".as_ptr() as *const c_char) };
        let resp_owned = if resp_ptr.is_null() {
            None
        } else {
            unsafe { CStr::from_ptr(resp_ptr) }
                .to_str()
                .ok()
                .map(str::to_string)
        };
        unsafe { xpc_release(reply) };

        let resp_str = resp_owned.ok_or_else(|| "daemon returned no response".to_string())?;
        let root: serde_json::Value = serde_json::from_str(&resp_str)
            .map_err(|e| format!("failed to parse response JSON: {e}"))?;

        match root.get("status").and_then(|s| s.as_str()) {
            Some("OK") => Ok(root),
            Some(other) => Err(format!("daemon returned error status: {other}")),
            None => Err("daemon response missing status field".to_string()),
        }
    }
}

impl Drop for CAClient {
    fn drop(&mut self) {
        unsafe {
            xpc_connection_cancel(self.conn);
            xpc_release(self.conn);
        }
    }
}
