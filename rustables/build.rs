use bindgen;

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::borrow::Cow;
use lazy_static::lazy_static;
use regex::{Captures, Regex};


/// Recast nft_*_attributes from u32 to u16 in header file `before`.
fn reformat_units(before: &str) -> Cow<str> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(pub type nft[a-zA-Z_]*_attributes) = u32;").unwrap();
    }
    RE.replace_all(before, |captures: &Captures| {
        format!("{} = u16;", &captures[1])
    })
}

fn main() {
    // Tell cargo to invalidate the built crate whenever the headers change.
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .generate_comments(false)
        .prepend_enum_name(false)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Add newlines because in alpine bindgen doesn't add them after statements.
    let s = bindings.to_string().replace(" ; ", ";\n");
    let s = reformat_units(&s);
    let h = String::from("#![allow(non_camel_case_types, dead_code)]\n\n") + &s;

    // Write the bindings to the rust header file.
    let out_path = PathBuf::from("src/tests/bindings.rs");
    File::create(out_path)
         .expect("Error: could not create rust header file.")
         .write_all(&h.as_bytes())
         .expect("Error: could not write to the rust header file.");
}
