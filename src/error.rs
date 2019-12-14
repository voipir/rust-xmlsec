//!
//! XmlSec High Level Error handling
//!


/// Wrapper project-wide Result typealias.
pub type XmlSecResult<T> = Result<T, XmlSecError>;


/// Wrapper project-wide Errors enumeration.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum XmlSecError
{
    KeyNotLoaded,
    KeyLoadError,

    RootNotFound,
    NodeNotFound,

    SigningError,
    VerifyError,
}


impl std::fmt::Display for XmlSecError
{
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result
    {
        match self
        {
            Self::KeyNotLoaded => write!(fmt, "{}", "Key has not yet been loaded and is required"),
            Self::KeyLoadError => write!(fmt, "{}", "Failed to load key"),

            Self::RootNotFound => write!(fmt, "{}", "Failed to find document root"),
            Self::NodeNotFound => write!(fmt, "{}", "Failed to find node"),

            Self::SigningError => write!(fmt, "{}", "An error has ocurred while attemting to sign document"),
            Self::VerifyError  => write!(fmt, "{}", "Verification failed"),
        }
    }
}


impl std::error::Error for XmlSecError
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)>
    {
        None
    }
}
