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
    Str(String),

    KeyNotLoaded,
    KeyLoadError,
    CertLoadError,

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
        {   Self::Str(reason) => write!(fmt, "{}", reason),

            Self::KeyNotLoaded  => write!(fmt, "{}", "Key has not yet been loaded and is required"),
            Self::KeyLoadError  => write!(fmt, "{}", "Failed to load key"),
            Self::CertLoadError => write!(fmt, "{}", "Failed to load certificate"),

            Self::RootNotFound => write!(fmt, "{}", "Failed to find document root"),
            Self::NodeNotFound => write!(fmt, "{}", "Failed to find node"),

            Self::SigningError => write!(fmt, "{}", "An error has ocurred while attemting to sign document"),
            Self::VerifyError  => write!(fmt, "{}", "Verification process failed"),
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


impl From<&str> for XmlSecError
{
    fn from(other: &str) -> Self
    {
        Self::Str(other.to_owned())
    }
}


impl From<String> for XmlSecError
{
    fn from(other: String) -> Self
    {
        Self::Str(other)
    }
}
