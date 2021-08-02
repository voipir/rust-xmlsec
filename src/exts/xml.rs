//!
//! XmlSec Extensions over LibXML2 Wrapper
//!
use crate::XmlSecResult;

use crate::XmlDocument;
use crate::XmlXPathContext;

use libxml::bindings; // FIXME requires common bindings generation over libxml2

use std::ffi::CString;
use std::os::raw::c_uchar;
use std::ptr::null_mut;


/// Extensions on XmlDocument for the usage by or with XmlSec.
pub trait XmlSecDocumentExt
{
    /// Specifies the name of an ID attribute on a set of nodes selected by an xpath search. See examples for usage.
    fn specify_idattr(&self, search: &str, idattr_name: &str, namespaces: Option<&[(&str, &str)]>) -> XmlSecResult<()>;
}


impl XmlSecDocumentExt for XmlDocument
{
    fn specify_idattr(&self, search: &str, idattr_name: &str, namespaces: Option<&[(&str, &str)]>) -> XmlSecResult<()>
    {
        let xpath = XmlXPathContext::new(self)
            .expect("Should not have failed to build xpath context XML document");

        if let Some(nss) = namespaces
        {
            for (prefix, href) in nss {
                xpath.register_namespace(prefix, href).ok();
            }
        }

        let result = match xpath.evaluate(search)
        {
            Ok(s)  => { s },
            Err(_) => { return Err(format!("Should not have failed while xpath searching for '{}'", search).into()); }
        };

        let subjnodes = result.get_nodes_as_vec();

        if subjnodes.is_empty()
        {
            return Err(
                format!("Could not find any nodes to specify ID attribute that go by the XPath: {}", search).into()
            );
        }

        for node in &subjnodes
        {
            if let Some(attrnode) = node.get_property_node(idattr_name)
            {
                let docptr  = self.doc_ptr();
                let attrptr = attrnode.node_ptr() as *mut bindings::_xmlAttr;

                let id     = attrnode.get_content();
                let cid    = CString::new(id.clone()).unwrap();
                let cidptr = cid.as_ptr() as *mut c_uchar;

                let existing = unsafe { bindings::xmlGetID(docptr, cidptr) };

                if existing.is_null() {
                    unsafe { bindings::xmlAddID(null_mut(), docptr, cidptr, attrptr) };
                } else if existing != attrptr {
                    return Err(format!("Error: duplicate ID attribute: {}", id).into());
                }
            }
        }

        Ok(())
    }
}
