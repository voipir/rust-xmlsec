//!
//! Wrapping for OpenSSL Crypto Backend Implementation for XmlSec Crypto Interface
//!
use crate::bindings;


/// Supported digesting and signing methods as specified by the XML standard.
#[allow(missing_docs)]
pub enum XmlSecSignatureMethod
{
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    // Aes128Gcm,
    // Aes192Gcm,
    // Aes256Gcm,
    KWAes128,
    KWAes192,
    KWAes256,
    Des3Cbc,
    KWDes3,
    DsaSha1,
    DsaSha256,
    EcdsaSha1,
    EcdsaSha224,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    // HmacMd5,
    HmacRipemd160,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    // Md5,
    Ripemd160,
    // RsaMd5,
    RsaRipemd160,
    RsaSha1,
    RsaSha224,
    RsaSha256,
    RsaSha384,
    RsaSha512,
    RsaPkcs1,
    RsaOaep,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}


impl XmlSecSignatureMethod
{
    /// Returns the resource pointer for the corresponding digesting/signing resource
    pub fn to_method(&self) -> bindings::xmlSecTransformId
    {
        match self
        {
            Self::Aes128Cbc     => unsafe { bindings::xmlSecOpenSSLTransformAes128CbcGetKlass() },
            Self::Aes192Cbc     => unsafe { bindings::xmlSecOpenSSLTransformAes192CbcGetKlass() },
            Self::Aes256Cbc     => unsafe { bindings::xmlSecOpenSSLTransformAes256CbcGetKlass() },
            // Self::Aes128Gcm     => unsafe { bindings::xmlSecOpenSSLTransformAes128GcmGetKlass() },
            // Self::Aes192Gcm     => unsafe { bindings::xmlSecOpenSSLTransformAes192GcmGetKlass() },
            // Self::Aes256Gcm     => unsafe { bindings::xmlSecOpenSSLTransformAes256GcmGetKlass() },
            Self::KWAes128      => unsafe { bindings::xmlSecOpenSSLTransformKWAes128GetKlass() },
            Self::KWAes192      => unsafe { bindings::xmlSecOpenSSLTransformKWAes192GetKlass() },
            Self::KWAes256      => unsafe { bindings::xmlSecOpenSSLTransformKWAes256GetKlass() },
            Self::Des3Cbc       => unsafe { bindings::xmlSecOpenSSLTransformDes3CbcGetKlass() },
            Self::KWDes3        => unsafe { bindings::xmlSecOpenSSLTransformKWDes3GetKlass() },
            Self::DsaSha1       => unsafe { bindings::xmlSecOpenSSLTransformDsaSha1GetKlass() },
            Self::DsaSha256     => unsafe { bindings::xmlSecOpenSSLTransformDsaSha256GetKlass() },
            Self::EcdsaSha1     => unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha1GetKlass() },
            Self::EcdsaSha224   => unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha224GetKlass() },
            Self::EcdsaSha256   => unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha256GetKlass() },
            Self::EcdsaSha384   => unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha384GetKlass() },
            Self::EcdsaSha512   => unsafe { bindings::xmlSecOpenSSLTransformEcdsaSha512GetKlass() },
            // Self::HmacMd5       => unsafe { bindings::xmlSecOpenSSLTransformHmacMd5GetKlass() },
            Self::HmacRipemd160 => unsafe { bindings::xmlSecOpenSSLTransformHmacRipemd160GetKlass() },
            Self::HmacSha1      => unsafe { bindings::xmlSecOpenSSLTransformHmacSha1GetKlass() },
            Self::HmacSha224    => unsafe { bindings::xmlSecOpenSSLTransformHmacSha224GetKlass() },
            Self::HmacSha256    => unsafe { bindings::xmlSecOpenSSLTransformHmacSha256GetKlass() },
            Self::HmacSha384    => unsafe { bindings::xmlSecOpenSSLTransformHmacSha384GetKlass() },
            Self::HmacSha512    => unsafe { bindings::xmlSecOpenSSLTransformHmacSha512GetKlass() },
            // Self::Md5           => unsafe { bindings::xmlSecOpenSSLTransformMd5GetKlass() },
            Self::Ripemd160     => unsafe { bindings::xmlSecOpenSSLTransformRipemd160GetKlass() },
            // Self::RsaMd5        => unsafe { bindings::xmlSecOpenSSLTransformRsaMd5GetKlass() },
            Self::RsaRipemd160  => unsafe { bindings::xmlSecOpenSSLTransformRsaRipemd160GetKlass() },
            Self::RsaSha1       => unsafe { bindings::xmlSecOpenSSLTransformRsaSha1GetKlass() },
            Self::RsaSha224     => unsafe { bindings::xmlSecOpenSSLTransformRsaSha224GetKlass() },
            Self::RsaSha256     => unsafe { bindings::xmlSecOpenSSLTransformRsaSha256GetKlass() },
            Self::RsaSha384     => unsafe { bindings::xmlSecOpenSSLTransformRsaSha384GetKlass() },
            Self::RsaSha512     => unsafe { bindings::xmlSecOpenSSLTransformRsaSha512GetKlass() },
            Self::RsaPkcs1      => unsafe { bindings::xmlSecOpenSSLTransformRsaPkcs1GetKlass() },
            Self::RsaOaep       => unsafe { bindings::xmlSecOpenSSLTransformRsaOaepGetKlass() },
            Self::Sha1          => unsafe { bindings::xmlSecOpenSSLTransformSha1GetKlass() },
            Self::Sha224        => unsafe { bindings::xmlSecOpenSSLTransformSha224GetKlass() },
            Self::Sha256        => unsafe { bindings::xmlSecOpenSSLTransformSha256GetKlass() },
            Self::Sha384        => unsafe { bindings::xmlSecOpenSSLTransformSha384GetKlass() },
            Self::Sha512        => unsafe { bindings::xmlSecOpenSSLTransformSha512GetKlass() },
        }
    }
}
