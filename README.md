# crtman - WIP

A minimal Certificate Authority daemon for macOS that stores its private key in the MacOS Keychain via Apple’s Security.framework, and uses OpenSSL’s low-level APIs to parse CSRs, build X.509 certificates, and generate CRLs. Communication is exposed over XPC with a JSON/newline protocol.

This project is a work in progress, see TODO file for next steps.

---

## Features

- **SEP Key Protection**
  CA private key is generated and protected with the Secure Enclave via `SecKeyCreateRandomKey`. An improvement would be to store the key itself in SEP. This requires app to be signed by a provisioning profile.
- **OpenSSL X.509 Handling**
  CSR parsing, certificate construction, and DER→PEM encoding use OpenSSL’s libcrypto API.
- **JSON-over-XPC Protocol**
  Simple JSON commands (`GetCACert`, `IssueCert`, `RevokeCert`, `GetCRL`) over XPC; easy to integrate from any language.
- **Pluggable “Profiles”**
  Control keyUsage/extensions by profile (`server`, `client`, `code-sign`, …).
- **Revocation & CRL**
  Maintain an on-disk index, generate and sign CRLs with Keychain key.
- **Thread-safe & Auditable**
  File-lock around your serial/index, detailed logging for audit.

---

## Security Considerations (TODO)

The following items should be addressed before using this in production:

### Key Protection
- **EC P-256 keys in Keychain**: The CA now uses EC P-256 keys (switched from RSA 3072). Keys are stored in the macOS Keychain, which is itself SEP-protected on Apple Silicon.
- **Optional Secure Enclave**: Build with `make USE_SEP=1` to enable true Secure Enclave key storage. However, this requires:
  - An Apple Developer Certificate (ad-hoc signing is insufficient)
  - Proper entitlements provisioned through Apple's developer portal
  - Potentially notarization for distribution
- **Current status**: Without Developer ID signing, keys are stored in the Keychain (SEP-encrypted at rest, but key material in RAM during signing).

### Access Control
- **No Mach service access control**: Any process running as the current user can connect to `com.nordsec.crtman` and issue/revoke certificates. Consider adding `xpc_connection_get_audit_token()` checks to restrict which applications can call the CA.

### Certificate Management
- **Serial number reuse risk**: The serial file allows serial reuse if corrupted/reset. CAs should never reuse serial numbers per RFC 5280.
- **No certificate database**: Issued certificates aren't stored—only `index.txt` with metadata. Cannot retrieve previously issued certs or audit what was issued.
- **Profiles not implemented**: The `profile` parameter is accepted but currently ignored. No keyUsage/extendedKeyUsage extensions are being set on issued certificates.

### Operational
- **Key re-provisioning on restart**: `provision_key = true` by default means a new CA keypair is generated each restart unless a config file exists. This would invalidate all previously issued certificates.

