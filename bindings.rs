//!
//! XmlSec Bindings Generation
//!
use bindgen::Builder   as BindgenBuilder;
use bindgen::Formatter as BindgenFormatter;

use pkg_config::Config as PkgConfig;

use std::env;
use std::path::PathBuf;
use std::process::Command;

const BINDINGS: &str = "bindings.rs";
const TRANSFORMS: &[(&str, &str)] = &[
    ("xmlSecOpenSSLTransformAes128CbcGetKlass", "has_aes128_cbc"),
    ("xmlSecOpenSSLTransformAes128GcmGetKlass", "has_aes128_gcm"),
    ("xmlSecOpenSSLTransformAes192CbcGetKlass", "has_aes192_cbc"),
    ("xmlSecOpenSSLTransformAes192GcmGetKlass", "has_aes192_gcm"),
    ("xmlSecOpenSSLTransformAes256CbcGetKlass", "has_aes256_cbc"),
    ("xmlSecOpenSSLTransformAes256GcmGetKlass", "has_aes256_gcm"),
    ("xmlSecOpenSSLTransformConcatKdfGetKlass", "has_concatkdf"),
    ("xmlSecOpenSSLTransformDes3CbcGetKlass", "has_des3_cbc"),
    ("xmlSecOpenSSLTransformDhEsGetKlass", "has_dhes"),
    ("xmlSecOpenSSLTransformDsaSha1GetKlass", "has_dsa_sha1"),
    ("xmlSecOpenSSLTransformDsaSha256GetKlass", "has_dsa_sha256"),
    ("xmlSecOpenSSLTransformEcdhGetKlass", "has_ecdh"),
    ("xmlSecOpenSSLTransformEcdsaRipemd160GetKlass", "has_ecdsa_ripemd160"),
    ("xmlSecOpenSSLTransformEcdsaSha1GetKlass", "has_ecdsa_sha1"),
    ("xmlSecOpenSSLTransformEcdsaSha224GetKlass", "has_ecdsa_sha224"),
    ("xmlSecOpenSSLTransformEcdsaSha256GetKlass", "has_ecdsa_sha256"),
    ("xmlSecOpenSSLTransformEcdsaSha3_224GetKlass", "has_ecdsa_sha3_224"),
    ("xmlSecOpenSSLTransformEcdsaSha3_256GetKlass", "has_ecdsa_sha3_256"),
    ("xmlSecOpenSSLTransformEcdsaSha3_384GetKlass", "has_ecdsa_sha3_384"),
    ("xmlSecOpenSSLTransformEcdsaSha3_512GetKlass", "has_ecdsa_sha3_512"),
    ("xmlSecOpenSSLTransformEcdsaSha384GetKlass", "has_ecdsa_sha384"),
    ("xmlSecOpenSSLTransformEcdsaSha512GetKlass", "has_ecdsa_sha512"),
    ("xmlSecOpenSSLTransformGost2001GostR3411_94GetKlass", "has_gost2001"),
    ("xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_256GetKlass", "has_gost2012_256"),
    ("xmlSecOpenSSLTransformGostR3410_2012GostR3411_2012_512GetKlass", "has_gost2012_512"),
    ("xmlSecOpenSSLTransformGostR3411_2012_256GetKlass", "has_gost2012_256"),
    ("xmlSecOpenSSLTransformGostR3411_2012_512GetKlass", "has_gost2012_512"),
    ("xmlSecOpenSSLTransformGostR3411_94GetKlass", "has_gost94"),
    ("xmlSecOpenSSLTransformHmacMd5GetKlass", "has_hmac_md5"),
    ("xmlSecOpenSSLTransformHmacRipemd160GetKlass", "has_hmac_ripemd160"),
    ("xmlSecOpenSSLTransformHmacSha1GetKlass", "has_hmac_sha1"),
    ("xmlSecOpenSSLTransformHmacSha224GetKlass", "has_hmac_sha224"),
    ("xmlSecOpenSSLTransformHmacSha256GetKlass", "has_hmac_sha256"),
    ("xmlSecOpenSSLTransformHmacSha384GetKlass", "has_hmac_sha384"),
    ("xmlSecOpenSSLTransformHmacSha512GetKlass", "has_hmac_sha512"),
    ("xmlSecOpenSSLTransformKWAes128GetKlass", "has_kw_aes128"),
    ("xmlSecOpenSSLTransformKWAes192GetKlass", "has_kw_aes192"),
    ("xmlSecOpenSSLTransformKWAes256GetKlass", "has_kw_aes256"),
    ("xmlSecOpenSSLTransformKWDes3GetKlass", "has_kw_des3"),
    ("xmlSecOpenSSLTransformMd5GetKlass", "has_md5"),
    ("xmlSecOpenSSLTransformPbkdf2GetKlass", "has_pbkdf2"),
    ("xmlSecOpenSSLTransformRipemd160GetKlass", "has_ripemd160"),
    ("xmlSecOpenSSLTransformRsaMd5GetKlass", "has_rsa_md5"),
    ("xmlSecOpenSSLTransformRsaOaepEnc11GetKlass", "has_rsaoaep_enc11"),
    ("xmlSecOpenSSLTransformRsaOaepGetKlass", "has_rsa_oaep"),
    ("xmlSecOpenSSLTransformRsaPkcs1GetKlass", "has_rsa_pkcs1"),
    ("xmlSecOpenSSLTransformRsaPssSha1GetKlass", "has_rsapsssha1"),
    ("xmlSecOpenSSLTransformRsaPssSha224GetKlass", "has_rsapsssha224"),
    ("xmlSecOpenSSLTransformRsaPssSha256GetKlass", "has_rsapsssha256"),
    ("xmlSecOpenSSLTransformRsaPssSha3_224GetKlass", "has_rsapsssha3_224"),
    ("xmlSecOpenSSLTransformRsaPssSha3_256GetKlass", "has_rsapsssha3_256"),
    ("xmlSecOpenSSLTransformRsaPssSha3_384GetKlass", "has_rsapsssha3_384"),
    ("xmlSecOpenSSLTransformRsaPssSha3_512GetKlass", "has_rsapsssha3_512"),
    ("xmlSecOpenSSLTransformRsaPssSha384GetKlass", "has_rsapsssha384"),
    ("xmlSecOpenSSLTransformRsaPssSha512GetKlass", "has_rsapsssha512"),
    ("xmlSecOpenSSLTransformRsaRipemd160GetKlass", "has_rsa_ripemd160"),
    ("xmlSecOpenSSLTransformRsaSha1GetKlass", "has_rsa_sha1"),
    ("xmlSecOpenSSLTransformRsaSha224GetKlass", "has_rsa_sha224"),
    ("xmlSecOpenSSLTransformRsaSha256GetKlass", "has_rsa_sha256"),
    ("xmlSecOpenSSLTransformRsaSha384GetKlass", "has_rsa_sha384"),
    ("xmlSecOpenSSLTransformRsaSha512GetKlass", "has_rsa_sha512"),
    ("xmlSecOpenSSLTransformSha1GetKlass", "has_sha1"),
    ("xmlSecOpenSSLTransformSha224GetKlass", "has_sha224"),
    ("xmlSecOpenSSLTransformSha256GetKlass", "has_sha256"),
    ("xmlSecOpenSSLTransformSha384GetKlass", "has_sha384"),
    ("xmlSecOpenSSLTransformSha512GetKlass", "has_sha512"),
    ("xmlSecOpenSSLTransformSha3_224GetKlass", "has_sha3_224"),
    ("xmlSecOpenSSLTransformSha3_256GetKlass", "has_sha3_256"),
    ("xmlSecOpenSSLTransformSha3_384GetKlass", "has_sha3_384"),
    ("xmlSecOpenSSLTransformSha3_512GetKlass", "has_sha3_512"),
];


fn main()
{
    println!("cargo:rustc-link-lib=xmlsec1-openssl");  // -lxmlsec1-openssl
    println!("cargo:rustc-link-lib=xmlsec1");          // -lxmlsec1
    println!("cargo:rustc-link-lib=xml2");             // -lxml2
    println!("cargo:rustc-link-lib=ssl");              // -lssl
    println!("cargo:rustc-link-lib=crypto");           // -lcrypto

    let path_out      = PathBuf::from(env::var("OUT_DIR").unwrap());
    let path_bindings = path_out.join(BINDINGS);

    if !path_bindings.exists()
    {
        PkgConfig::new()
            .probe("xmlsec1")
            .expect("Could not find xmlsec1 using pkg-config");

        let bindbuild = BindgenBuilder::default()
            .header("bindings.h")
            .clang_args(fetch_xmlsec_config_flags())
            .clang_args(fetch_xmlsec_config_libs())
            .layout_tests(true)
            .formatter(BindgenFormatter::default())
            .generate_comments(true);

        let bindings = bindbuild.generate()
            .expect("Unable to generate bindings");

        bindings.write_to_file(path_bindings)
            .expect("Couldn't write bindings!");
    }

    for (symbol, cfg) in TRANSFORMS {
        println!("cargo:rustc-check-cfg=cfg({})", cfg);
        detect_transform(symbol, cfg);
    }
}

/// Try to compile a tiny program referencing a symbol.
/// If it succeeds, emit a `cfg` flag like `has_aes128`.
fn detect_transform(symbol: &str, cfg_name: &str) {
    let code = format!(
        "#include <xmlsec/crypto.h>\n\
         int main() {{ (void){}(); return 0; }}",
        symbol
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let src_file = out_dir.join(format!("probe_{cfg}.c", cfg = cfg_name));
    std::fs::write(&src_file, code).unwrap();

    let exe_file = out_dir.join(format!("probe_{cfg}", cfg = cfg_name));

    let mut cmd = cc::Build::new().get_compiler().to_command();
    cmd.arg(&src_file).arg("-o").arg(&exe_file);

    // add cflags
    for flag in fetch_xmlsec_config_flags() {
        cmd.arg(flag);
    }
    // add libs
    for lib in fetch_xmlsec_config_libs() {
        cmd.arg(lib);
    }

    match cmd.status() {
        Ok(status) if status.success() => {
            println!("cargo:rustc-cfg={}", cfg_name);
        }
        Ok(status) => {
            println!("cargo:warning=Probe for {} failed", cfg_name);
        }
        Err(e) => {
            println!("cargo:warning=Probe for {} failed to run: {}", cfg_name, e);
        }
    }
}

fn fetch_xmlsec_config_flags() -> Vec<String>
{
    let out = Command::new("xmlsec1-config")
        .arg("--cflags")
        .output()
        .expect("Failed to get --cflags from xmlsec1-config. Is xmlsec1 installed?")
        .stdout;

    args_from_output(out)
}


fn fetch_xmlsec_config_libs() -> Vec<String>
{
    let out = Command::new("xmlsec1-config")
        .arg("--libs")
        .output()
        .expect("Failed to get --libs from xmlsec1-config. Is xmlsec1 installed?")
        .stdout;

    args_from_output(out)
}


fn args_from_output(args: Vec<u8>) -> Vec<String>
{
    let decoded = String::from_utf8(args)
        .expect("Got invalid UTF8 from xmlsec1-config");

    let args = decoded.split_whitespace()
        .map(|p| p.to_owned())
        .collect::<Vec<String>>();

    args
}
