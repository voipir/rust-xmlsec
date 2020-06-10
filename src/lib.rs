//!
//! Bindings for XmlSec1
//!
//! Modules reflect the header names of the bound xmlsec1 library
//!
#![deny(missing_docs)]

// imports
use lazy_static::lazy_static;

#[doc(hidden)]
pub use libxml::tree::node::Node as XmlNode;
#[doc(hidden)]
pub use libxml::tree::document::Document as XmlDocument;
#[doc(hidden)]
pub use libxml::xpath::Context as XmlXPathContext;

// internals
mod bindings;

mod exts;
mod keys;
mod error;
mod crypto;
mod xmlsec;
mod xmldsig;
mod templates;
mod transforms;

// exports
pub use self::exts::XmlSecDocumentExt;

pub use self::keys::XmlSecKey;
pub use self::keys::XmlSecKeyFormat;

pub use self::error::XmlSecError;
pub use self::error::XmlSecResult;

pub use self::crypto::XmlSecSignatureMethod;

pub use self::xmldsig::XmlSecSignatureContext;

pub use self::templates::TemplateBuilder            as XmlSecTemplateBuilder;
pub use self::templates::XmlDocumentTemplating      as XmlSecDocumentTemplating;
pub use self::templates::XmlDocumentTemplateBuilder as XmlSecDocumentTemplateBuilder;

pub use self::transforms::XmlSecCanonicalizationMethod;

// export preambles
pub mod template {
    //! Namespace for preamble pertaining all things signature template creation.

    pub mod preamble {
        //! Preamble of all things signature template creation.
        pub use crate::XmlSecTemplateBuilder;
        pub use crate::XmlSecDocumentTemplating;
        pub use crate::XmlSecCanonicalizationMethod;
        pub use crate::XmlSecSignatureMethod;
    }
}
