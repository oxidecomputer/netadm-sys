// Copyright 2021 Oxide Computer Company
//
// Derived from https://github.com/oxidecomputer/libscf-sys/blob/main/build.rs

use bindgen;
use std::env;
use std::path::PathBuf;

fn main() {
    #[cfg(not(target_os = "illumos"))]
    compile_error!("netadm-sys is only supported on illumos");

    println!("cargo:rustc-link-lib=kstat");
    println!("cargo:rerun-if-changed=wrapper.h");

    if let Err(_) = env::var("LIBCLANG_PATH") {
        env::set_var("LIBCLANG_PATH", "/opt/ooce/clang-11.0/lib");
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("unable to write bindings");

}
