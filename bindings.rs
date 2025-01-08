//!
//! XmlSec Bindings Generation
//!
use bindgen::Builder as BindgenBuilder;
use bindgen::Formatter as BindgenFormatter;

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

const BINDINGS: &str = "bindings.rs";

fn main() {
    let dependencies = locate_and_link_dependencies();

    let path_out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let path_bindings = path_out.join(BINDINGS);

    if !path_bindings.exists() {
        let bindbuild = BindgenBuilder::default()
            .header("bindings.h")
            .allowlist_type("xml.*")
            .allowlist_function("xml.*")
            .allowlist_var("xml.*")
            .clang_args(dependencies.clang_args())
            .layout_tests(true)
            .formatter(BindgenFormatter::default())
            .generate_comments(true);

        let bindings = bindbuild.generate().expect("Unable to generate bindings");

        bindings
            .write_to_file(path_bindings)
            .expect("Couldn't write bindings!");
    }
}

struct LocatedDependencies {
    include_paths: Vec<PathBuf>,
    defines: HashMap<String, Option<String>>,
}

impl LocatedDependencies {
    fn clang_args(&self) -> Vec<String> {
        let mut result = Vec::new();
        for include_path in &self.include_paths {
            result.push(format!("-I{}", include_path.display()));
        }
        for (define, value) in &self.defines {
            match value {
                Some(value) => result.push(format!("-D{}={}", define, value)),
                None => result.push(format!("-D{}", define)),
            }
        }
        result
    }
}

#[cfg(not(windows))]
fn locate_and_link_dependencies() -> LocatedDependencies {
    let library =
        pkg_config::probe_library("xmlsec1").expect("Could not find xmlsec1 using pkg-config");

    LocatedDependencies {
        include_paths: library.include_paths,
        defines: library.defines,
    }
}

#[cfg(windows)]
fn locate_and_link_dependencies() -> LocatedDependencies {
    let library =
        vcpkg::find_package("xmlsec").expect("Failed to find xmlsec using vcpkg. Is it installed?");

    println!("cargo:rustc-link-lib=crypt32");
    println!("cargo:rustc-link-lib=user32");
    println!("cargo:rustc-link-lib=bcrypt");

    // vcpkg does not provide the defines, so we have to provide them ourselves
    // -DXMLSEC_DL_LIBLTDL=1 -DXMLSEC_CRYPTO_OPENSSL=1
    let mut defines = HashMap::new();
    defines.insert("__XMLSEC_FUNCTION__".into(), Some("__func__".into()));
    defines.insert("XMLSEC_NO_SIZE_T".into(), None);
    defines.insert("XMLSEC_DL_LIBLTDL".into(), Some("1".into()));
    defines.insert("XMLSEC_CRYPTO_OPENSSL".into(), Some("1".into()));
    defines.insert("XMLSEC_NO_CRYPTO_DYNAMIC_LOADING".into(), Some("1".into()));
    defines.insert("XMLSEC_NO_GOST".into(), Some("1".into()));
    defines.insert("XMLSEC_NO_GOST2012".into(), Some("1".into()));

    LocatedDependencies {
        include_paths: library.include_paths,
        defines,
    }
}
