//!
//! Unit Tests for Key
//!
use xmlsec::XmlSecKey;
use xmlsec::XmlSecKeyFormat;


#[test]
fn test_key_cert_loading_file()
{
    let key = XmlSecKey::from_file("tests/resources/key.pem", XmlSecKeyFormat::Pem, None)
        .expect("Failed to properly load key for test");

    key.load_cert_from_file("tests/resources/key.crt", XmlSecKeyFormat::Pem)
        .expect("Failed to properly load key certificate for test");
}


#[test]
fn test_key_cert_loading_memory()
{
    let keybuff = std::fs::read("tests/resources/key.pem")
        .expect("Failed to read file for testing key/cert from memory load");

    let crtbuff = std::fs::read("tests/resources/key.crt")
        .expect("Failed to read file for testing key/cert from memory load");

    let key = XmlSecKey::from_memory(&keybuff, XmlSecKeyFormat::Pem, None)
        .expect("Failed to properly load key for test");

    key.load_cert_from_memory(&crtbuff, XmlSecKeyFormat::Pem)
        .expect("Failed to properly load key certificate for test");
}


#[test]
fn test_key_name_handing()
{
    let mut key = XmlSecKey::from_file("tests/resources/key.pem", XmlSecKeyFormat::Pem, None)
        .expect("Failed to properly load key for test");

    key.set_name("testname");

    let name = key.get_name();

    assert_eq!(name, "testname");
}
