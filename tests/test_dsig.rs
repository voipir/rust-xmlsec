//!
//! Unit Tests for DSig Context
//!
use xmlsec::XmlSecKey;
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
        panic!(e);
    }

    // compare signature results
    let reference = String::from_utf8(
        include_bytes!("./resources/sign1-res.xml").to_vec()
    ).unwrap();

    assert_eq!(doc.to_string(), reference);
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
            panic!(e)
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
            panic!(format!("Failed while verify signature. Caused by: {}", e));
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
