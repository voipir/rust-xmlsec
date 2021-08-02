//!
//! Wrapper for XmlSec Signature Context
//!
use crate::bindings;

use crate::XmlSecKey;
use crate::XmlSecError;
use crate::XmlSecResult;

use crate::XmlNode;
use crate::XmlDocument;

use std::os::raw::c_uchar;
use std::ptr::null_mut;


/// Signature signing/veryfying context
pub struct XmlSecSignatureContext
{
    ctx: *mut bindings::xmlSecDSigCtx,
}


impl XmlSecSignatureContext
{
    /// Builds a context, ensuring xmlsec is initialized.
    pub fn new() -> Self
    {
        crate::xmlsec::guarantee_xmlsec_init();

        let ctx = unsafe { bindings::xmlSecDSigCtxCreate(null_mut()) };

        if ctx.is_null() {
            panic!("Failed to create dsig context");
        }

        Self {ctx}
    }

    /// Sets the key to use for signature or verification. In case a key had
    /// already been set, the latter one gets released in the optional return.
    pub fn insert_key(&mut self, key: XmlSecKey) -> Option<XmlSecKey>
    {
        let mut old = None;

        unsafe {
            if ! (*self.ctx).signKey.is_null() {
                old = Some(XmlSecKey::from_ptr((*self.ctx).signKey));
            }

            (*self.ctx).signKey = XmlSecKey::leak(key);
        }

        old
    }

    /// Releases a currently set key returning `Some(key)` or None otherwise.
    pub fn release_key(&mut self) -> Option<XmlSecKey>
    {
        unsafe {
            if (*self.ctx).signKey.is_null() {
                None
            } else {
                let key = XmlSecKey::from_ptr((*self.ctx).signKey);

                (*self.ctx).signKey = null_mut();

                Some(key)
            }
        }
    }

    /// UNTESTED
    pub fn sign_node(&self, node: &XmlNode) -> XmlSecResult<()>
    {
        self.key_is_set()?;

        let node = node.node_ptr() as bindings::xmlNodePtr;

        self.sign_node_raw(node)
    }

    /// Takes a [`XmlDocument`][xmldoc] and attempts to sign it. For this to work it has to have a properly structured
    /// `<dsig:Signature>` node within, and a XmlSecKey must have been previously set with [`insert_key`][inskey].
    ///
    /// # Errors
    ///
    /// If key has not been previously set or document is malformed.
    ///
    /// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
    /// [inskey]: struct.XmlSecSignatureContext.html#method.insert_key
    pub fn sign_document(&self, doc: &XmlDocument) -> XmlSecResult<()>
    {
        self.key_is_set()?;

        let root = find_root(doc)?;
        let sig  = find_signode(root)?;

        self.sign_node_raw(sig)
    }

    /// UNTESTED
    pub fn verify_node(&self, node: &XmlNode) -> XmlSecResult<bool>
    {
        self.key_is_set()?;

        let node = node.node_ptr() as bindings::xmlNodePtr;

        self.verify_node_raw(node)
    }

    /// Takes a [`XmlDocument`][xmldoc] and attempts to verify its signature. For this to work it has to have a properly
    /// structured and signed `<dsig:Signature>` node within, and a XmlSecKey must have been previously set with
    /// [`insert_key`][inskey].
    ///
    /// # Errors
    ///
    /// If key has not been previously set or document is malformed.
    ///
    /// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
    /// [inskey]: struct.XmlSecSignatureContext.html#method.insert_key
    pub fn verify_document(&self, doc: &XmlDocument) -> XmlSecResult<bool>
    {
        self.key_is_set()?;

        let root = find_root(doc)?;
        let sig  = find_signode(root)?;

        self.verify_node_raw(sig)
    }
}


impl XmlSecSignatureContext
{
    fn key_is_set(&self) -> XmlSecResult<()>
    {
        unsafe {
            if ! (*self.ctx).signKey.is_null() {
                Ok(())
            } else {
                Err(XmlSecError::KeyNotLoaded)
            }
        }
    }

    fn sign_node_raw(&self, node: *mut bindings::xmlNode) -> XmlSecResult<()>
    {
        let rc = unsafe { bindings::xmlSecDSigCtxSign(self.ctx, node) };

        if rc < 0 {
            Err(XmlSecError::SigningError)
        } else {
            Ok(())
        }
    }

    fn verify_node_raw(&self, node: *mut bindings::xmlNode) -> XmlSecResult<bool>
    {
        let rc = unsafe { bindings::xmlSecDSigCtxVerify(self.ctx, node) };

        if rc < 0 {
            return Err(XmlSecError::VerifyError);
        }

        match unsafe { (*self.ctx).status }
        {
            bindings::xmlSecDSigStatus_xmlSecDSigStatusUnknown   => Ok(false),
            bindings::xmlSecDSigStatus_xmlSecDSigStatusSucceeded => Ok(true),
            bindings::xmlSecDSigStatus_xmlSecDSigStatusInvalid   => Ok(false),

            _ => panic!("Failed to interprete xmlSecDSigStatus code")
        }
    }
}


impl Drop for XmlSecSignatureContext
{
    fn drop(&mut self)
    {
        unsafe { bindings::xmlSecDSigCtxDestroy(self.ctx) };
    }
}



fn find_root(doc: &XmlDocument) -> XmlSecResult<*mut bindings::xmlNode>
{
    if let Some(root) = doc.get_root_element()
    {
        let rawroot = root.node_ptr() as *mut bindings::xmlNode;
        let signode = find_signode(rawroot)?;

        Ok(signode)
    } else {
        Err(XmlSecError::RootNotFound)
    }
}


fn find_signode(tree: *mut bindings::xmlNode) -> XmlSecResult<*mut bindings::xmlNode>
{
    let signode = unsafe {bindings::xmlSecFindNode(
        tree,
        &bindings::xmlSecNodeSignature as *const c_uchar,
        &bindings::xmlSecDSigNs        as *const c_uchar,
    ) };

    if signode.is_null() {
        return Err(XmlSecError::NodeNotFound);
    }

    Ok(signode)
}
