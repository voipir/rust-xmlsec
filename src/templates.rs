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
use std::ptr::null;
use std::os::raw::c_uchar;


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
    fn id(self, id: &str) -> Self;

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

    id: Option<String>,
}


impl Default for TemplateOptions
{
    fn default() -> Self
    {
        Self {
            c14n: XmlSecCanonicalizationMethod::ExclusiveC14N,
            sig:  XmlSecSignatureMethod::RsaSha1,
            id:   None
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

    fn id(mut self, id: &str) -> Self
    {
        self.options.id = Some(id.to_owned());
        self
    }

    fn done(self) -> XmlSecResult<()>
    {
        let cid = self.options.id.map(|p| CString::new(p).unwrap());

        let docptr = self.doc.doc_ptr() as *mut bindings::xmlDoc;

        let rootptr;
        if let Some(root) = self.doc.get_root_element() {
            rootptr = root.node_ptr() as *mut bindings::xmlNode;
        } else {
            return Err(XmlSecError::RootNotFound);
        }

        let signature = unsafe { bindings::xmlSecTmplSignatureCreate(
            docptr,
            self.options.c14n.to_method(),
            self.options.sig.to_method(),
            if cid.is_some() {cid.unwrap().as_ptr() as *const c_uchar} else {null()}
        ) };

        if signature.is_null() {
            panic!("Failed to create signature template");
        }

        let reference = unsafe { bindings::xmlSecTmplSignatureAddReference(
            signature,
            XmlSecSignatureMethod::Sha1.to_method(),
            null(),
            null(),
            null()
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
            panic!("Failed to add key info");
        }

        let keyname = unsafe { bindings::xmlSecTmplKeyInfoAddKeyName(keyinfo, null()) };

        if keyname.is_null() {
            panic!("Failed to add key name");
        }

        unsafe { bindings::xmlAddChild(rootptr, signature) };

        Ok(())
    }
}
