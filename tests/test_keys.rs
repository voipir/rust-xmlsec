//!
//! Unit Tests for Key
//!
use xmlsec::XmlSecKey;
use xmlsec::XmlSecKeyFormat;


#[test]
fn test_key_loading()
{
    XmlSecKey::from_file("tests/resources/key.pem", XmlSecKeyFormat::Pem, None)
        .expect("Failed to properly load key for test");
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
