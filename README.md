# Rust wrapper for xmlsec1

This library aims at wrapping xmlsec1 and being interoperable with [rust-libxml](https://github.com/KWARC/rust-libxml), while attemting to be as correct and comfortable to use as possible.

## Things needing improvement

- Better input sanitization of string arguments. Currently they get blindly turned into a FFI version and passed through to xmlsec.
- Proper management for xmlsec error handling. Currently things fail very opaquely without actually telling you why the signing process failed, just that it failed for the particular job.
- More expressive error handling chain.

## Things not yet supported

- XML encryption.
- Key management (as in xmlsec key manager). Though the value of wrapping that should be debated first. It may be more sensible to lift that to pure Rust instead.
- Dynamic selection of crypto backend.

## Contibuting

Help in any way improving or completing the wrapping of xmlsec features always very welcome! Please keep some things in mind before PR'ing your changes;

- Please check tests for breakage and write new ones to cover your changes.
- Please run valgrind over your tests and make sure you are not leaking resources.

## Tested platforms

- Debian Buster (10.x)
