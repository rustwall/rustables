extern crate pkg_config;

use std::env;
use std::path::PathBuf;

#[cfg(feature = "nftnl-1-1-0")]
const MIN_VERSION: &str = "1.1.0";

#[cfg(all(feature = "nftnl-1-0-9", not(feature = "nftnl-1-1-0")))]
const MIN_VERSION: &str = "1.0.9";

#[cfg(all(feature = "nftnl-1-0-8", not(feature = "nftnl-1-0-9")))]
const MIN_VERSION: &str = "1.0.8";

#[cfg(all(feature = "nftnl-1-0-7", not(feature = "nftnl-1-0-8")))]
const MIN_VERSION: &str = "1.0.7";

#[cfg(not(feature = "nftnl-1-0-7"))]
const MIN_VERSION: &str = "1.0.6";

fn main() {
    if let Ok(lib_dir) = env::var("LIBNFTNL_LIB_DIR").map(PathBuf::from) {
        if !lib_dir.is_dir() {
            panic!(
                "libnftnl library directory does not exist: {}",
                lib_dir.display()
            );
        }
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=nftnl");
    } else {
        // Trying with pkg-config instead
        println!("Minimum libnftnl version: {}", MIN_VERSION);
        pkg_config::Config::new()
            .atleast_version(MIN_VERSION)
            .probe("libnftnl")
            .unwrap();
    }

    if let Ok(lib_dir) = env::var("LIBMNL_LIB_DIR").map(PathBuf::from) {
        if !lib_dir.is_dir() {
            panic!(
                "libmnl library directory does not exist: {}",
                lib_dir.display()
            );
        }
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
        println!("cargo:rustc-link-lib=mnl");
    } else {
        // Trying with pkg-config instead
        pkg_config::Config::new()
            .atleast_version("1.0.0")
            .probe("libmnl")
            .unwrap();
    }
}
