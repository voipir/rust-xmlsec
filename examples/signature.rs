//!
//! Signature Creation and Verification Example
//!
// use xmlsec::template::preamble::*;  // would include all in the block right below this line
use xmlsec::XmlSecTemplateBuilder;
use xmlsec::XmlSecDocumentTemplating;
use xmlsec::XmlSecCanonicalizationMethod;
use xmlsec::XmlSecSignatureMethod;

use xmlsec::XmlSecKey;
use xmlsec::XmlSecKeyFormat;
use xmlsec::XmlSecSignatureContext;

use xmlsec::XmlSecDocumentExt;

use libxml::parser::Parser           as XmlParser;
use libxml::tree::document::Document as XmlDocument;


fn main()
{
    let parser = XmlParser::default();

    let document = parser.parse_file("tests/resources/sign2-doc.xml")
        .expect("Failed to load document create template for and sign/verify");

    create_template(&document);
    create_signature(&document);
    verify_signature(&document);
}


fn create_template(doc: &XmlDocument)
{
    doc.template()
        .canonicalization(XmlSecCanonicalizationMethod::ExclusiveC14N)
        .signature(XmlSecSignatureMethod::RsaSha1)
        .done()
        .expect("Failed to create/attach signature template");
}


fn create_signature(doc: &XmlDocument)
{
    let key = XmlSecKey::from_file("tests/resources/key.pem", XmlSecKeyFormat::Pem, None)
        .expect("Failed to properly load key from file");

    let mut sigctx = XmlSecSignatureContext::new();
    sigctx.insert_key(key);

    sigctx.sign_document(doc)
        .expect("Failed to sign document");
}


fn verify_signature(doc: &XmlDocument)
{
    let key = XmlSecKey::from_file("tests/resources/key.pem", XmlSecKeyFormat::Pem, None)
        .expect("Failed to properly load key from file");

    let mut sigctx = XmlSecSignatureContext::new();
    sigctx.insert_key(key);

    // optionaly specify the attribute ID names in the nodes you are verifying
    doc.specify_idattr("//prefix:DataNodes", "MyIDAttrName", Some(&[("prefix", "namespace")]))
        .expect(
            "Could not specify ID attr name. This error specifies whether no nodes where found \
            or if there was an attr name collision."
        );

    let valid = sigctx.verify_document(doc)
        .expect("Failed to verify document");

    if !valid {
        panic!("Document signature is not valid");
    }
}
