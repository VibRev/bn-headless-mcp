//! Link the executable against `libbinaryninjacore`.
//!
//! `binaryninjacore-sys` declares `links = "binaryninjacore"` and emits the
//! directory holding the shared object as `DEP_BINARYNINJACORE_PATH`. Cargo
//! propagates a `links` crate's linker flags to *libraries* automatically but not
//! to the final executable, so without this file the build fails at link time with
//! undefined `BN*` symbols even though the dependency built fine.
//!
//! The rpath entry is what lets the binary run without `LD_LIBRARY_PATH` set.
//! `BINARYNINJADIR` still has to be set at *build* time — that is what
//! `binaryninjacore-sys` reads to find the core in the first place.
fn main() {
    let Some(link_path) = std::env::var_os("DEP_BINARYNINJACORE_PATH") else {
        panic!(
            "DEP_BINARYNINJACORE_PATH is unset. Set BINARYNINJADIR to your Binary Ninja \
             installation directory before building; see README.md."
        );
    };
    let link_path = link_path.to_string_lossy().into_owned();
    println!("cargo::rustc-link-lib=dylib=binaryninjacore");
    println!("cargo::rustc-link-search={link_path}");
    #[cfg(target_os = "linux")]
    println!("cargo::rustc-link-arg=-Wl,-rpath,{link_path},-L{link_path}");
    #[cfg(target_os = "macos")]
    println!("cargo::rustc-link-arg=-Wl,-rpath,{link_path}");
}
