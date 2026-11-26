fn main() {
    // The native socket and interface reader (native/sockets.c): compiled against the macOS SDK's
    // own headers, so libproc's struct layouts are exact. macOS only.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rerun-if-changed=native/sockets.c");
        cc::Build::new().file("native/sockets.c").warnings(true).compile("bb_native");
        // File Shield's real-time watch (native/fsevents.c): FSEvents, from CoreServices.
        println!("cargo:rerun-if-changed=native/fsevents.c");
        cc::Build::new().file("native/fsevents.c").warnings(true).compile("bb_fsevents");
        println!("cargo:rustc-link-lib=framework=CoreServices");
    }
}
