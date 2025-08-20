//!
//! Unit Tests for DSig Context
//!

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use xmlsec::{UriResource, XmlSecKey};
use xmlsec::XmlSecKeyFormat;
use xmlsec::XmlSecSignatureContext;
use xmlsec::XmlSecDocumentExt;

use libxml::parser::Parser as XmlParser;


#[test]
fn test_dsig_context_creation()
{
    XmlSecSignatureContext::new();
}


#[test]
fn test_dsig_key_setting()
{
    let mut ctx = XmlSecSignatureContext::new();

    let key = XmlSecKey::from_file("tests/resources/key.pem", XmlSecKeyFormat::Pem, None)
        .expect("Failed to properly load key for test");

    let key_ptr = unsafe { key.as_ptr() };

    let oldkey = ctx.insert_key(key);

    assert!(oldkey.is_none(), "It should never have been set at this point");

    let newkey = ctx.release_key()
        .expect("Should have had a set key now being released");

    let newkey_ptr = unsafe { newkey.as_ptr() };

    assert_eq!(key_ptr, newkey_ptr, "Key should have remained to be exactly the same");
}


#[test]
fn test_signing_template()
{
    let ctx = common_setup_context_and_key();

    let doc = XmlParser::default()
        .parse_file("tests/resources/sign1-tmpl.xml")
        .expect("Failed to load signature template");

    if let Err(e) = ctx.sign_document(&doc) {
        panic!("{}", e);
    }

    // compare signature results
    let reference = String::from_utf8(
        include_bytes!("./resources/sign1-res.xml").to_vec()
    ).unwrap();

    assert_eq!(doc.to_string(), reference);
}

#[test]
fn test_signing_template_with_uri_file_mapping()
{
    let mut ctx = common_setup_context_and_key();
    ctx.set_uri_mapping({
        let mut map = HashMap::new();
        map.insert(
            "data.json".to_string(),
            UriResource::Path(PathBuf::from("tests/resources/data.json")),
        );
        map
    });

    let doc = XmlParser::default()
        .parse_file("tests/resources/sign4-tmpl.xml")
        .expect("Failed to load signature template");

    if let Err(e) = ctx.sign_document(&doc) {
        panic!("{}", e);
    }

    // compare signature results
    let reference = String::from_utf8(
        include_bytes!("./resources/sign4-signed.xml").to_vec()
    ).unwrap();

    let signed_doc = doc.to_string();

    assert_eq!(signed_doc, reference);
}

#[test]
fn test_signing_template_with_uri_memory_mapping()
{
    let mut ctx = common_setup_context_and_key();
    ctx.set_uri_mapping({
        let mut map = HashMap::new();
        map.insert(
            "data.json".to_string(),
            UriResource::Data(r#"{
  "some": "additional file"
}"#.as_bytes().to_vec()),
        );
        map
    });

    let doc = XmlParser::default()
        .parse_file("tests/resources/sign4-tmpl.xml")
        .expect("Failed to load signature template");

    if let Err(e) = ctx.sign_document(&doc) {
        panic!("{}", e);
    }

    // compare signature results
    let reference = String::from_utf8(
        include_bytes!("./resources/sign4-signed.xml").to_vec()
    ).unwrap();

    let signed_doc = doc.to_string();

    assert_eq!(signed_doc, reference);
}


#[test]
fn test_verify_template_signature()
{
    let ctx = common_setup_context_and_key();

    let doc = XmlParser::default()
        .parse_file("tests/resources/sign1-res.xml")
        .expect("Failed to load signature for verification testing");

    match ctx.verify_document(&doc)
    {
        Ok(valid) => {
            if !valid {
                panic!("Signature in testing resources should have returned to be valid");
            }
        }

        Err(e) => {
            panic!("{}", e)
        }
    }
}


#[test]
fn test_verify_custom_id_signature()
{
    let ctx = common_setup_context_and_key();

    let doc = XmlParser::default()
        .parse_file("tests/resources/sign3-signed.xml")
        .expect("Failed to load signature for verification testing");

    doc.specify_idattr("//sig:Data", "ThisID", Some(&[("sig", "urn:envelope")]))
        .expect("Unable to set 'ThisID' as the ID attribute name");

    match ctx.verify_document(&doc)
    {
        Ok(valid) => {
            if !valid {
                panic!("Signature in testing resources should have returned to be valid");
            }
        }

        Err(e) => {
            panic!("Failed while verify signature. Caused by: {}", e);
        }
    }
}


fn common_setup_context_and_key() -> XmlSecSignatureContext
{
   let mut ctx = XmlSecSignatureContext::new();

   let key = XmlSecKey::from_file("tests/resources/key.pem", XmlSecKeyFormat::Pem, None)
       .expect("Failed to properly load key for test");

    ctx.insert_key(key);

    ctx
}
