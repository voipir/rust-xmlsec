//!
//! Testing of Template Creation
//!
use xmlsec::XmlSecTemplateBuilder;
use xmlsec::XmlSecDocumentTemplating;
use xmlsec::XmlSecCanonicalizationMethod;
use xmlsec::XmlSecSignatureMethod;

use libxml::parser::Parser as XmlParser;


#[test]
fn test_template_creation()
{
    // load document
    let parser = XmlParser::default();

    let doc = parser.parse_file("tests/resources/sign2-doc.xml")
        .expect("Could not load template document");

    // add signature node structure
    doc.template()
        .canonicalization(XmlSecCanonicalizationMethod::ExclusiveC14N)
        .signature(XmlSecSignatureMethod::RsaSha1)
        .keyname(true)
        .keyvalue(true)
        .x509data(true)
        .uri("ReferencedID")
        .done()
        .expect("Failed to build and attach signature");

    // compare template results
    let reference = String::from_utf8(
        include_bytes!("./resources/sign2-tmpl.xml").to_vec()
    ).unwrap();

    assert_eq!(doc.to_string(), reference);
}
