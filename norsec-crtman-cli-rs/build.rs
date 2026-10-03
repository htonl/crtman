fn main() {
    // Compile the small C shim that provides the Objective-C block used for
    // the XPC connection event handler. Rust cannot construct ObjC block
    // literals, so we delegate that one bit of work to C.
    cc::Build::new()
        .file("xpc_shim.c")
        .warnings(false)
        .compile("xpc_shim");

    // XPC symbols live in libSystem (always linked). libdispatch is a separate
    // library; on macOS its dylib only exists in the dyld shared cache, but the
    // SDK ships a .tbd that the linker can consume. Point the linker at the
    // SDK's copy of /usr/lib/system so `-ldispatch` resolves.
    let sdk = sdk_path();
    if let Ok(ref p) = sdk {
        println!("cargo:rustc-link-search=native={}/usr/lib/system", p);
    }
    println!("cargo:rustc-link-lib=dispatch");

    // CoreFoundation declared for safety.
    println!("cargo:rustc-link-arg=-framework");
    println!("cargo:rustc-link-arg=CoreFoundation");
}

fn sdk_path() -> std::io::Result<String> {
    let out = std::process::Command::new("xcrun")
        .arg("--show-sdk-path")
        .output()?;
    let path = String::from_utf8(out.stdout)
        .ok()
        .map(|s| s.trim().to_string());
    match path {
        Some(p) if !p.is_empty() => Ok(p),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "could not determine macOS SDK path",
        )),
    }
}
