//!
//! Wrapper for XmlSec Signature Context
//!

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::fs::File;
use std::io::Read;
use crate::bindings;

use crate::XmlSecError;
use crate::XmlSecKey;
use crate::XmlSecResult;

use crate::XmlDocument;
use crate::XmlNode;

use std::mem::{forget, MaybeUninit};
use std::os::raw::c_uchar;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::slice;
use std::sync::Once;

thread_local! {
    static THREAD_URI_MAP: RefCell<HashMap<String, UriResource>> = RefCell::new(HashMap::new());
    static THREAD_EXECUTING: Cell<bool> = Cell::new(false);
    static INIT_IO: Once = Once::new();
}

#[derive(Clone)]
/// Either a file path to the resource or the value itself
pub enum UriResource {
    /// The local file path to the resource
    Path(PathBuf),
    /// The value of the resource
    Data(Vec<u8>),
}

#[repr(C)]
struct MemCtx {
    data: Vec<u8>,
    offset: usize,
}

#[repr(C)]
struct IoCtx {
    kind: i32, // 0 = File, 1 = Memory
    file: MaybeUninit<File>,
    memory:  MaybeUninit<MemCtx>,
}

unsafe extern "C" fn io_match_cb(filename: *const c_char) -> c_int {
    if filename.is_null() { return 0; }
    let uri = CStr::from_ptr(filename).to_string_lossy().into_owned();
    let matched = THREAD_URI_MAP.with(|map| map.borrow().contains_key(&uri));
    if matched { 1 } else { 0 }
}

unsafe extern "C" fn io_open_cb(filename: *const c_char) -> *mut c_void {
    if filename.is_null() { return null_mut(); }
    let uri = CStr::from_ptr(filename).to_string_lossy().into_owned();
    let resource_opt = THREAD_URI_MAP.with(|map| map.borrow().get(&uri).cloned());
    match resource_opt {
        Some(UriResource::Path(p)) => {
            match File::open(p) {
                Ok(f) => {
                    let file_ctx = IoCtx {
                        kind: 0,
                        file: MaybeUninit::new(f),
                        memory:  MaybeUninit::uninit(),
                    };
                    Box::into_raw(Box::new(file_ctx)) as *mut c_void
                },
                Err(_) => null_mut(),
            }
        },
        Some(UriResource::Data(data)) => {
            let memory_ctx = MemCtx { data, offset: 0 };
            let ctx = IoCtx {
                kind: 1,
                file: MaybeUninit::uninit(),
                memory:  MaybeUninit::new(memory_ctx),
            };
            Box::into_raw(Box::new(ctx)) as *mut c_void
        },
        None => null_mut(),
    }
}

unsafe extern "C" fn io_read_cb(ctx: *mut c_void, buffer: *mut c_char, len: c_int) -> c_int {
    if ctx.is_null() || buffer.is_null() { return -1; }
    let ctx = &mut *(ctx as *mut IoCtx);
    match ctx.kind {
        0 => {
            let file = ctx.file.assume_init_mut();
            let buf = slice::from_raw_parts_mut(buffer as *mut u8, len as usize);
            match file.read(buf) {
                Ok(n) => n as c_int,
                Err(_) => -1,
            }
        }
        1 => {
            let mem = ctx.memory.assume_init_mut();
            let remaining = mem.data.len() - mem.offset;
            let to_read = remaining.min(len as usize);
            let dst = slice::from_raw_parts_mut(buffer as *mut u8, to_read);
            dst.copy_from_slice(&mem.data[mem.offset..mem.offset + to_read]);
            mem.offset += to_read;
            to_read as c_int
        }
        _ => -1,
    }
}

unsafe extern "C" fn io_close_cb(ctx: *mut c_void) -> c_int {
    if ctx.is_null() { return -1; }
    drop(Box::from_raw(ctx as *mut IoCtx));
    0
}

/// Signature signing/veryfying context
pub struct XmlSecSignatureContext
{
    ctx: *mut bindings::xmlSecDSigCtx,
    uri_mapping: Option<HashMap<String, UriResource>>,
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

        Self {ctx, uri_mapping: None}
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

    /// Maps the given URI to the defined local file paths
    pub fn set_uri_mapping(&mut self, map: HashMap<String, UriResource>) {
        self.uri_mapping = Some(map);
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

        self.execute_with_mapping(|| {
            let root = find_root(doc)?;
            let sig = find_signode(root)?;

            self.sign_node_raw(sig)
        })
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

        self.execute_with_mapping(|| {
            let root = find_root(doc)?;
            let sig  = find_signode(root)?;

            self.verify_node_raw(sig)
        })
    }

    /// Register IO-Callbacks once for the thread.
    fn register_io_callbacks_if_needed() {
        INIT_IO.with(|once| {
            once.call_once(|| unsafe {
                if bindings::xmlSecIORegisterCallbacks(
                    Some(io_match_cb),
                    Some(io_open_cb),
                    Some(io_read_cb),
                    Some(io_close_cb),
                ) < 0 {
                    panic!("Failed to register custom IO callbacks");
                }
            });
        });
    }

    /// Helper method that executes the given action after preparing the URI map for the thread
    fn execute_with_mapping<F, R>(&self, action: F) -> XmlSecResult<R>
    where
        F: FnOnce() -> XmlSecResult<R>,
    {
        Self::register_io_callbacks_if_needed();

        THREAD_EXECUTING.with(|flag| {
            if flag.get() {
                return Err(XmlSecError::ParallelExecution);
            }
            flag.set(true);

            // Set mapping in static thread constant
            if let Some(ref map) = self.uri_mapping {
                THREAD_URI_MAP.with(|cell| {
                    *cell.borrow_mut() = map.clone();
                });
            }

            let result = action();

            // Reset static thread constant
            THREAD_URI_MAP.with(|cell| {
                cell.borrow_mut().clear();
            });
            flag.set(false);
            result
        })
    }

    /// # Safety
    ///
    /// Returns a raw pointer to the underlying xmlsec signature context. Beware that it is still managed by this
    /// wrapping object and will be deallocated once `self` gets dropped.
    pub unsafe fn as_ptr(&self) -> *mut bindings::xmlSecDSigCtx
    {
        self.ctx
    }

    /// # Safety
    ///
    /// Returns a raw pointer to the underlying xmlsec signature context. Beware that it will be forgotten by this
    /// wrapping object and *must* be deallocated manually by the callee.
    pub unsafe fn into_ptr(self) -> *mut bindings::xmlSecDSigCtx
    {
        let ctx = self.ctx;  // keep a copy of the pointer

        forget(self);  // release our copy of the pointer without deallocating it

        ctx  // return the only remaining copy
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
