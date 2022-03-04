//!
//! Wrapper for DSIG Nodes Templating
//!
use crate::bindings;

use crate::XmlDocument;

use crate::XmlSecCanonicalizationMethod;
use crate::XmlSecSignatureMethod;

use crate::XmlSecError;
use crate::XmlSecResult;

use std::ffi::CString;
use std::os::raw::c_uchar;
use std::ptr::null;

/// Declaration of a template building API for other specific trait extensions
/// on foreign XML objects.
pub trait TemplateBuilder
{
    /// Sets canonicalization method. See: [`XmlSecCanonicalizationMethod`][c14n].
    ///
    /// [c14n]: ./transforms/enum.XmlSecCanonicalizationMethod.html
    fn canonicalization(self, c14n: XmlSecCanonicalizationMethod) -> Self;

    /// Sets cryptographic signature method. See: [`XmlSecSignatureMethod`][sig].
    ///
    /// [sig]: ./crypto/openssl/enum.XmlSecSignatureMethod.html
    fn signature(self, sig: XmlSecSignatureMethod) -> Self;

    /// Sets signature subject node URI
    fn uri(self, uri: &str) -> Self;

    /// the namespace prefix for the signature element (e.g. "dsig")
    fn ns_prefix(self, ns_prefix: &str) -> Self;

    /// Adds <ds:KeyName> to key information node
    fn keyname(self, add: bool) -> Self;

    /// Adds <ds:KeyValue> to key information node
    fn keyvalue(self, add: bool) -> Self;

    /// Adds <ds:X509Data> to key information node
    fn x509data(self, add: bool) -> Self;

    /// Builds the actual template and returns
    fn done(self) -> XmlSecResult<()>;
}

/// Trait extension aimed at a concrete implementation for [`XmlDocument`][xmldoc]
///
/// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
pub trait XmlDocumentTemplating<'d>
{
    /// Return a template builder over current XmlDocument.
    fn template(&'d self) -> XmlDocumentTemplateBuilder<'d>;
}

/// Concrete template builder for [`XmlDocument`][xmldoc]
///
/// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
pub struct XmlDocumentTemplateBuilder<'d>
{
    doc:     &'d XmlDocument,
    options: TemplateOptions,
}

struct TemplateOptions
{
    c14n: XmlSecCanonicalizationMethod,
    sig:  XmlSecSignatureMethod,

    ns_prefix: Option<String>,
    uri:       Option<String>,

    keyname:  bool,
    keyvalue: bool,
    x509data: bool,
}

impl Default for TemplateOptions
{
    fn default() -> Self
    {
        Self {
            c14n: XmlSecCanonicalizationMethod::ExclusiveC14N,
            sig:  XmlSecSignatureMethod::RsaSha1,

            uri:       None,
            ns_prefix: None,

            keyname:  false,
            keyvalue: false,
            x509data: false,
        }
    }
}

impl<'d> XmlDocumentTemplating<'d> for XmlDocument
{
    fn template(&'d self) -> XmlDocumentTemplateBuilder<'d>
    {
        crate::xmlsec::guarantee_xmlsec_init();

        XmlDocumentTemplateBuilder {doc: self, options: TemplateOptions::default()}
    }
}

impl<'d> TemplateBuilder for XmlDocumentTemplateBuilder<'d>
{
    fn canonicalization(mut self, c14n: XmlSecCanonicalizationMethod) -> Self
    {
        self.options.c14n = c14n;
        self
    }

    fn signature(mut self, sig: XmlSecSignatureMethod) -> Self
    {
        self.options.sig = sig;
        self
    }

    fn uri(mut self, uri: &str) -> Self
    {
        self.options.uri = Some(uri.to_owned());
        self
    }

    fn ns_prefix(mut self, ns_prefix: &str) -> Self
    {
        self.options.ns_prefix = Some(ns_prefix.to_owned());
        self
    }

    fn keyname(mut self, add: bool) -> Self
    {
        self.options.keyname = add;
        self
    }

    fn keyvalue(mut self, add: bool) -> Self
    {
        self.options.keyvalue = add;
        self
    }

    fn x509data(mut self, add: bool) -> Self
    {
        self.options.x509data = add;
        self
    }

    fn done(self) -> XmlSecResult<()>
    {
        let curi = {
            if let Some(uri) = self.options.uri {
                CString::new(uri).unwrap().into_raw() as *const c_uchar
            } else {
                null()
            }
        };

        let c_ns_prefix = {
            if let Some(ns_prefix) = self.options.ns_prefix {
                CString::new(ns_prefix).unwrap().into_raw() as *const c_uchar
            } else {
                null()
            }
        };

        let docptr = self.doc.doc_ptr() as *mut bindings::xmlDoc;

        let rootptr = if let Some(root) = self.doc.get_root_element() {
            root.node_ptr() as *mut bindings::xmlNode
        } else {
            return Err(XmlSecError::RootNotFound);
        };

        let signature = unsafe { bindings::xmlSecTmplSignatureCreateNsPref(
            docptr,
            self.options.c14n.to_method(),
            self.options.sig.to_method(),
            null(),
            c_ns_prefix,
        ) };

        if signature.is_null() {
            panic!("Failed to create signature template");
        }

        let reference = unsafe { bindings::xmlSecTmplSignatureAddReference(
            signature,
            XmlSecSignatureMethod::Sha1.to_method(),
            null(),
            curi,
            null(),
        ) };

        if reference.is_null() {
            panic!("Failed to add enveloped transform to reference");
        }

        let envelope = unsafe { bindings::xmlSecTmplReferenceAddTransform(reference, bindings::xmlSecTransformEnvelopedGetKlass()) };

        if envelope.is_null() {
            panic!("Failed to add enveloped transform")
        }

        let keyinfo = unsafe { bindings::xmlSecTmplSignatureEnsureKeyInfo(signature, null()) };

        if keyinfo.is_null() {
            panic!("Failed to ensure key info");
        }

        if self.options.keyname
        {
            let keyname = unsafe { bindings::xmlSecTmplKeyInfoAddKeyName(keyinfo, null()) };

            if keyname.is_null() {
                panic!("Failed to add key name");
            }
        }

        if self.options.keyvalue
        {
            let keyvalue = unsafe { bindings::xmlSecTmplKeyInfoAddKeyValue(keyinfo) };

            if keyvalue.is_null() {
                panic!("Failed to add key value");
            }
        }

        if self.options.x509data
        {
            let x509data = unsafe { bindings::xmlSecTmplKeyInfoAddX509Data(keyinfo) };

            if x509data.is_null() {
                panic!("Failed to add key value");
            }
        }

        unsafe { bindings::xmlAddChild(rootptr, signature) };

        Ok(())
    }
}
