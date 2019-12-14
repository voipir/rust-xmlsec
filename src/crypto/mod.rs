//!
//! Crypto Backend Wrappings
//!

// TODO do proper selection for the backend depending on env var set for xmlsec crypto

// mod nss;
// pub use nss::XmlSecSignatureMethod;

// mod gcrypt;
// pub use gcrypt::XmlSecSignatureMethod;

// mod gnutls;
// pub use gnutls::XmlSecSignatureMethod;

mod openssl;
pub use openssl::XmlSecSignatureMethod;
