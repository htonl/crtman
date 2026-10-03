//! Thin CLI wrapper over the crtman daemon's XPC API.
//!
//! Rewritten in Rust. Mirrors the behavior and exit codes of the original
//! `norsec-crtman-cli.c`:
//!
//! ```
//! norsec-crtman-cli list-identities
//! norsec-crtman-cli add-identity NAME [--signed-by NAME]
//! norsec-crtman-cli get-ca-cert [--identity NAME]
//! norsec-crtman-cli issue-cert [--identity NAME] [--valid-days N] [--profile NAME]
//! norsec-crtman-cli get-crl [--identity NAME]
//! ```
//!
//! Exit codes: 0 success, 1 runtime error, 2 bad usage. The CLI does no crypto
//! itself; everything is delegated to the crtman daemon.

mod xpc;

use std::io::{Read, Write};
use std::process::ExitCode;

use serde_json::json;
use xpc::CAClient;

fn usage(out: &mut impl Write) -> u8 {
    let _ = write!(
        out,
        "usage:\n\
         norsec-crtman-cli list-identities\n\
         norsec-crtman-cli add-identity NAME [--signed-by NAME]\n\
         norsec-crtman-cli get-ca-cert [--identity NAME]\n\
         norsec-crtman-cli issue-cert [--identity NAME] [--valid-days N] [--profile NAME]\n\
         norsec-crtman-cli get-crl [--identity NAME]\n"
    );
    2
}

/// Connect to the daemon, or return the exit code to use on failure.
fn connect() -> Result<CAClient, u8> {
    match CAClient::new() {
        Ok(c) => Ok(c),
        Err(e) => {
            eprintln!("ca_client_init failed: {e}");
            Err(1)
        }
    }
}

/// Write a byte slice to stdout, flushing. Returns the exit code on error.
fn emit_to_stdout(data: &[u8]) -> u8 {
    let mut out = std::io::stdout();
    match out.write_all(data).and_then(|_| out.flush()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("write to stdout failed: {e}");
            1
        }
    }
}

fn cmd_list_identities() -> u8 {
    let c = match connect() {
        Ok(c) => c,
        Err(rc) => return rc,
    };
    let req = json!({ "cmd": "ListSigningIdentities" });
    match c.send(&req) {
        Ok(resp) => {
            let Some(arr) = resp.get("identities") else {
                eprintln!("list-identities: response missing 'identities'");
                return 1;
            };
            let Some(s) = serde_json::to_string_pretty(arr).ok() else {
                eprintln!("list-identities: failed to serialize identities");
                return 1;
            };
            let mut buf = s.into_bytes();
            buf.push(b'\n');
            emit_to_stdout(&buf)
        }
        Err(e) => {
            eprintln!("list-identities failed: {e}");
            1
        }
    }
}

fn cmd_add_identity(identity: &str, signed_by: Option<&str>) -> u8 {
    let c = match connect() {
        Ok(c) => c,
        Err(rc) => return rc,
    };
    let mut req = serde_json::Map::new();
    req.insert("cmd".into(), json!("AddSigningIdentity"));
    req.insert("identity".into(), json!(identity));
    if let Some(sb) = signed_by {
        req.insert("signed_by".into(), json!(sb));
    }
    match c.send(&serde_json::Value::Object(req)) {
        Ok(resp) => {
            let Some(pem) = resp.get("ca_cert_pem").and_then(|v| v.as_str()) else {
                eprintln!("add-identity: response missing 'ca_cert_pem'");
                return 1;
            };
            emit_to_stdout(pem.as_bytes())
        }
        Err(e) => {
            eprintln!("add-identity failed: {e}");
            1
        }
    }
}

fn cmd_get_ca_cert(identity: Option<&str>) -> u8 {
    let c = match connect() {
        Ok(c) => c,
        Err(rc) => return rc,
    };
    let mut req = serde_json::Map::new();
    req.insert("cmd".into(), json!("GetCACert"));
    if let Some(id) = identity {
        req.insert("identity".into(), json!(id));
    }
    match c.send(&serde_json::Value::Object(req)) {
        Ok(resp) => {
            let Some(pem) = resp.get("ca_cert_pem").and_then(|v| v.as_str()) else {
                eprintln!("get-ca-cert: response missing 'ca_cert_pem'");
                return 1;
            };
            emit_to_stdout(pem.as_bytes())
        }
        Err(e) => {
            eprintln!("get-ca-cert failed: {e}");
            1
        }
    }
}

fn cmd_issue_cert(identity: Option<&str>, valid_days: u64, profile: &str) -> u8 {
    let csr = match read_all_stdin() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read stdin failed: {e}");
            return 1;
        }
    };
    if csr.is_empty() {
        eprintln!("issue-cert: empty stdin (expected PEM CSR)");
        return 1;
    }
    let csr_pem = String::from_utf8(csr).unwrap_or_default();

    let c = match connect() {
        Ok(c) => c,
        Err(rc) => return rc,
    };
    let mut req = serde_json::Map::new();
    req.insert("cmd".into(), json!("IssueCert"));
    req.insert("csr_pem".into(), json!(csr_pem));
    req.insert("valid_days".into(), json!(valid_days));
    req.insert("profile".into(), json!(profile));
    if let Some(id) = identity {
        req.insert("identity".into(), json!(id));
    }
    match c.send(&serde_json::Value::Object(req)) {
        Ok(resp) => {
            let (Some(cert), Some(serial)) = (
                resp.get("cert_pem").and_then(|v| v.as_str()),
                resp.get("serial").and_then(|v| v.as_str()),
            ) else {
                eprintln!("issue-cert: response missing 'cert_pem'/'serial'");
                return 1;
            };
            let rc = emit_to_stdout(cert.as_bytes());
            if rc != 0 {
                return rc;
            }
            let mut err = std::io::stderr();
            match writeln!(err, "serial={serial}") {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("write to stderr failed: {e}");
                    1
                }
            }
        }
        Err(e) => {
            eprintln!("issue-cert failed: {e}");
            1
        }
    }
}

fn cmd_get_crl(identity: Option<&str>) -> u8 {
    let c = match connect() {
        Ok(c) => c,
        Err(rc) => return rc,
    };
    let mut req = serde_json::Map::new();
    req.insert("cmd".into(), json!("GetCRL"));
    if let Some(id) = identity {
        req.insert("identity".into(), json!(id));
    }
    match c.send(&serde_json::Value::Object(req)) {
        Ok(resp) => {
            let Some(pem) = resp.get("crl_pem").and_then(|v| v.as_str()) else {
                eprintln!("get-crl: response missing 'crl_pem'");
                return 1;
            };
            emit_to_stdout(pem.as_bytes())
        }
        Err(e) => {
            eprintln!("get-crl failed: {e}");
            1
        }
    }
}

/// Read all of stdin into a Vec<u8>.
fn read_all_stdin() -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    std::io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return ExitCode::from(usage(&mut std::io::stderr()));
    }
    let cmd = args[1].as_str();

    let rc = match cmd {
        "list-identities" => cmd_list_identities(),
        "add-identity" => {
            if args.len() < 3 {
                return ExitCode::from(usage(&mut std::io::stderr()));
            }
            let mut signed_by: Option<String> = None;
            let mut i = 3usize;
            while i < args.len() {
                if args[i] == "--signed-by" && i + 1 < args.len() {
                    signed_by = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("unknown arg: {}", args[i]);
                    return ExitCode::from(usage(&mut std::io::stderr()));
                }
            }
            cmd_add_identity(&args[2], signed_by.as_deref())
        }
        "get-ca-cert" | "get-crl" => {
            let mut identity: Option<String> = None;
            let mut i = 2usize;
            while i < args.len() {
                if args[i] == "--identity" && i + 1 < args.len() {
                    identity = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("unknown arg: {}", args[i]);
                    return ExitCode::from(usage(&mut std::io::stderr()));
                }
            }
            if cmd == "get-ca-cert" {
                cmd_get_ca_cert(identity.as_deref())
            } else {
                cmd_get_crl(identity.as_deref())
            }
        }
        "issue-cert" => {
            let mut identity: Option<String> = None;
            let mut valid_days: u64 = 365;
            let mut profile: String = "server".to_string();
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--identity" if i + 1 < args.len() => {
                        identity = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--valid-days" if i + 1 < args.len() => match args[i + 1].parse::<u64>() {
                        Ok(v) => {
                            valid_days = v;
                            i += 2;
                        }
                        Err(_) => {
                            eprintln!("invalid --valid-days: {}", args[i + 1]);
                            return ExitCode::from(usage(&mut std::io::stderr()));
                        }
                    },
                    "--profile" if i + 1 < args.len() => {
                        profile = args[i + 1].clone();
                        i += 2;
                    }
                    _ => {
                        eprintln!("unknown arg: {}", args[i]);
                        return ExitCode::from(usage(&mut std::io::stderr()));
                    }
                }
            }
            cmd_issue_cert(identity.as_deref(), valid_days, &profile)
        }
        "-h" | "--help" => {
            usage(&mut std::io::stdout());
            0
        }
        _ => usage(&mut std::io::stderr()),
    };
    ExitCode::from(rc)
}
