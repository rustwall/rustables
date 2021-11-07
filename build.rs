use bindgen;
use lazy_static::lazy_static;
use pkg_config;
use regex::{Captures, Regex};
use std::borrow::Cow;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

const SYS_HEADER_FILE: &str = "wrapper.h";
const SYS_BINDINGS_FILE: &str = "src/sys.rs";
const TESTS_HEADER_FILE: &str = "tests_wrapper.h";
const TESTS_BINDINGS_FILE: &str = "tests/sys.rs";
const MIN_LIBNFTNL_VERSION: &str = "1.0.6";
const MIN_LIBMNL_VERSION: &str = "1.0.0";

fn get_env(var: &'static str) -> Option<PathBuf> {
    println!("cargo:rerun-if-env-changed={}", var);
    env::var_os(var).map(PathBuf::from)
}

/// Set env vars to help rustc find linked libraries.
fn setup_libs() -> Vec<String> {
    let mut res = vec![];

    if let Some(lib_dir) = get_env("LIBNFTNL_LIB_DIR") {
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
        println!("Minimum libnftnl version: {}", MIN_LIBNFTNL_VERSION);
        let pkg_config_res = pkg_config::Config::new()
            .atleast_version(MIN_LIBNFTNL_VERSION)
            .probe("libnftnl")
            .unwrap();
        for path in pkg_config_res.include_paths {
            res.push(format!("-I{}", path.to_str().unwrap()));
        }
    }

    if let Some(lib_dir) = get_env("LIBMNL_LIB_DIR") {
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
            .atleast_version(MIN_LIBMNL_VERSION)
            .probe("libmnl")
            .unwrap();
    }

    res
}

/// Recast nft_*_attributes from u32 to u16 in header file `before`.
fn reformat_units(before: &str) -> Cow<str> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(pub type nft[a-zA-Z_]*_attributes) = u32;").unwrap();
    }
    RE.replace_all(before, |captures: &Captures| {
        format!("{} = u16;", &captures[1])
    })
}

fn generate_consts(clang_args: impl Iterator<Item = String>) {
    // Tell cargo to invalidate the built crate whenever the headers change.
    println!("cargo:rerun-if-changed={}", SYS_HEADER_FILE);

    let bindings = bindgen::Builder::default()
        .header(SYS_HEADER_FILE)
        .clang_args(clang_args)
        .generate_comments(false)
        .prepend_enum_name(false)
        .use_core()
        .whitelist_function("^nftnl_.+$")
        .whitelist_type("^nftnl_.+$")
        .whitelist_var("^nftnl_.+$")
        .whitelist_var("^NFTNL_.+$")
        .blacklist_type("(FILE|iovec)")
        .blacklist_type("^_IO_.+$")
        .blacklist_type("^__.+$")
        .blacklist_type("nlmsghdr")
        .raw_line("#![allow(non_camel_case_types)]\n\n")
        .raw_line("pub use libc;")
        .raw_line("use libc::{c_char, c_int, c_ulong, c_void, iovec, nlmsghdr, FILE};")
        .raw_line("use core::option::Option;")
        .ctypes_prefix("libc")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Error: unable to generate bindings");

    let mut s = bindings.to_string()
                    // Add newlines because in alpine bindgen doesn't add them after
                    // statements.
                    .replace(" ; ", ";\n")
                    .replace("#[derive(Debug, Copy, Clone)]", "");
    let re = Regex::new(r"libc::(c_[a-z]*)").unwrap();
    s = re.replace_all(&s, "$1").into();
    let re = Regex::new(r"::core::option::(Option)").unwrap();
    s = re.replace_all(&s, "$1").into();
    let re = Regex::new(r"_bindgen_ty_[0-9]+").unwrap();
    s = re.replace_all(&s, "u32").into();
    // Change struct bodies to c_void.
    let re = Regex::new(r"(pub struct .*) \{\n    *_unused: \[u8; 0\],\n\}\n").unwrap();
    s = re.replace_all(&s, "$1(c_void);\n").into();
    let re = Regex::new(r"pub type u32 = u32;\n").unwrap();
    s = re.replace_all(&s, "").into();

    // Write the bindings to the rust header file.
    let out_path = PathBuf::from(SYS_BINDINGS_FILE);
    File::create(out_path)
        .expect("Error: could not create rust header file.")
        .write_all(&s.as_bytes())
        .expect("Error: could not write to the rust header file.");
}

fn generate_test_consts() {
    // Tell cargo to invalidate the built crate whenever the headers change.
    println!("cargo:rerun-if-changed={}", TESTS_HEADER_FILE);

    let bindings = bindgen::Builder::default()
        .header(TESTS_HEADER_FILE)
        .generate_comments(false)
        .prepend_enum_name(false)
        .raw_line("#![allow(non_camel_case_types, dead_code)]\n\n")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Error: unable to generate bindings needed for tests.");

    // Add newlines because in alpine bindgen doesn't add them after statements.
    let s = bindings.to_string().replace(" ; ", ";\n");
    let s = reformat_units(&s);

    // Write the bindings to the rust header file.
    let out_path = PathBuf::from(TESTS_BINDINGS_FILE);
    File::create(out_path)
        .expect("Error: could not create rust header file.")
        .write_all(&s.as_bytes())
        .expect("Error: could not write to the rust header file.");
}

fn main() {
    let clang_args = setup_libs();
    generate_consts(clang_args.into_iter());
    generate_test_consts();
}
