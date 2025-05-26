# crtman

A minimal Certificate Authority daemon for macOS that stores its private key in the Secure Enclave (SEP) via Apple’s Security.framework, and uses OpenSSL’s low-level APIs to parse CSRs, build X.509 certificates, and generate CRLs. Communication is exposed over a TLS-wrapped UNIX or TCP socket with a JSON/newline protocol.

---

## Features

- **SEP Key Protection**
  CA private key is generated and pinned inside the Secure Enclave via `SecKeyCreateRandomKey`, never exposed in clear on disk.
- **OpenSSL X.509 Handling**
  CSR parsing, certificate construction, and DER→PEM encoding use OpenSSL’s libcrypto API.
- **JSON-over-TLS Protocol**
  Simple JSON commands (`GetCACert`, `IssueCert`, `RevokeCert`, `GetCRL`) over a socket; easy to integrate from any language.
- **Pluggable “Profiles”**
  Control keyUsage/extensions by profile (`server`, `client`, `code-sign`, …).
- **Revocation & CRL**
  Maintain an on-disk index, generate and sign CRLs with SEP.
- **Thread-safe & Auditable**
  File-lock around your serial/index, detailed logging for audit.

