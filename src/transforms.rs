//!
//! Wrapper for XmlSec Tranformation Methods
//!
use crate::bindings;


/// Supported canonical methods as specified by the XML standard.
#[allow(missing_docs)]
pub enum XmlSecCanonicalizationMethod
{
    InclusiveC14N,
    InclusiveC14NWithComments,
    InclusiveC14N11,
    InclusiveC14N11WithComments,
    ExclusiveC14N,
    ExclusiveC14NWithComments,
}


impl XmlSecCanonicalizationMethod
{
    /// Returns the resource pointer for the corresponding canonicalization ressource
    pub fn to_method(&self) -> bindings::xmlSecTransformId
    {
        match self
        {
            Self::InclusiveC14N               => unsafe { bindings::xmlSecTransformInclC14NGetKlass() },
            Self::InclusiveC14NWithComments   => unsafe { bindings::xmlSecTransformInclC14NWithCommentsGetKlass() },
            Self::InclusiveC14N11             => unsafe { bindings::xmlSecTransformInclC14N11GetKlass() },
            Self::InclusiveC14N11WithComments => unsafe { bindings::xmlSecTransformInclC14N11WithCommentsGetKlass() },
            Self::ExclusiveC14N               => unsafe { bindings::xmlSecTransformExclC14NGetKlass() },
            Self::ExclusiveC14NWithComments   => unsafe { bindings::xmlSecTransformExclC14NWithCommentsGetKlass() },
        }
    }
}
