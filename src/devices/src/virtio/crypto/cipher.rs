use std::convert::From;
use std::{fmt,ptr};
use std::mem::size_of;

use crate::virtio::crypto::{Error, Result};
use crate::virtio::DescriptorChain;
use crate::virtio::crypto::request::{
    CreateSessionResponse,
    next_read_descriptor,
    next_write_descriptor,
};

use vm_memory::{
    GuestAddress, GuestMemoryMmap, ByteValued, Bytes
};

use crypto_ioctls::Crypto;
use crypto_bindings::*;

use crate::virtio::crypto::{
    VIRTIO_CRYPTO_SYM_SESS_OP_SPEC_HDR_SIZE,
    VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE
};
use virtio_gen::virtio_crypto::*;

#[repr(C)]
#[derive(Clone, Copy)]
struct SymCreateRequest {
    pub op_flf: [u8; VIRTIO_CRYPTO_SYM_SESS_OP_SPEC_HDR_SIZE],
    pub op_type: u32,
    padding: u32,
}

impl Default for SymCreateRequest {
    fn default() -> SymCreateRequest {
        SymCreateRequest {
            op_flf: [0; VIRTIO_CRYPTO_SYM_SESS_OP_SPEC_HDR_SIZE],
            op_type: 0,
            padding: 0,
        }
    }
}

unsafe impl ByteValued for SymCreateRequest {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CipherRequest {
    pub algo: u32,
    pub key_len: u32,
    pub op: u32,
    padding: u32,
}

unsafe impl ByteValued for CipherRequest {}

#[derive(Clone, Copy)]
pub enum CipherOperation {
    Encrypt,
    Decrypt,
    Unsupported(u32),
}

impl From<u32> for CipherOperation {
    fn from(value: u32) -> Self {
        match value {
            VIRTIO_CRYPTO_OP_ENCRYPT => CipherOperation::Encrypt,
            VIRTIO_CRYPTO_OP_DECRYPT => CipherOperation::Decrypt,
            t => CipherOperation::Unsupported(t),
        }
    }
}

impl fmt::Display for CipherOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CipherOperation::Encrypt => write!(f, "encrypt"),
            CipherOperation::Decrypt => write!(f, "decrypt"),
            CipherOperation::Unsupported(t) => {
                write!(f, "'Unsupported ({})'", t)
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SymDataRequest {
    op_flf: [u8; VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE],
    op_type: u32,
    padding: u32,
}

impl Default for SymDataRequest {
    fn default() -> SymDataRequest {
        SymDataRequest {
            op_flf: [0; VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE],
            op_type: 0,
            padding: 0,
        }
    }
}

unsafe impl ByteValued for SymDataRequest {}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CipherDataRequest {
    pub iv_len: u32,
    pub src_data_len: u32,
    pub dst_data_len: u32,
    padding: u32,
}

unsafe impl ByteValued for CipherDataRequest {}

#[cfg(target_endian = "little")]
pub fn create_cipher_session(
    memory: &GuestMemoryMmap,
    flf_addr: GuestAddress,
    vlf_addr: GuestAddress,
    status_addr: GuestAddress,
    dev: &Crypto,
) -> Result<u32> {
    let req: SymCreateRequest = memory
        .read_obj(flf_addr)
        .map_err(Error::GuestMemory)?;

    let mut resp = CreateSessionResponse::default();

    match req.op_type {
        VIRTIO_CRYPTO_SYM_OP_CIPHER => {
            // Field op_flf of our SymCreateRequest contains a CipherRequest
            // struct
            let cipher : CipherRequest = memory
                .read_obj(flf_addr)
                .map_err(Error::GuestMemory)?;

            let mut key = vec![0u8; cipher.key_len as usize];
            memory.read_slice(&mut key, vlf_addr).map_err(Error::GuestMemory)?;
            let mut sess = session_op {
                cipher: cipher.algo,
                mac: 0,
                keylen: cipher.key_len,
                key: key.as_mut_ptr(),
                ..Default::default()
            };

            match dev.create_session(&mut sess) {
                Ok(()) => {
                    resp.session_id = sess.ses as u64;
                    resp.status = VIRTIO_CRYPTO_OK;
                }
                _ => {
                    resp.status = VIRTIO_CRYPTO_ERR;
                }
            }

            resp.session_id = sess.ses as u64;
            resp.status = VIRTIO_CRYPTO_OK;
            
            memory.write_obj(resp, status_addr)
                .map_err(Error::GuestMemory)?;
        }
        _ => {
            resp.status = VIRTIO_CRYPTO_NOTSUPP;
            memory.write_obj(resp, status_addr).map_err(Error::GuestMemory)?;
        }
    }
    
    Ok(size_of::<CreateSessionResponse>() as u32)
}

pub fn destroy_cipher_session(
    memory: &GuestMemoryMmap,
    flf_addr: GuestAddress,
    status_addr: GuestAddress,
    dev: &Crypto,
) -> Result<u32> {
    let sess_id: u64 = memory
        .read_obj(flf_addr)
        .map_err(Error::GuestMemory)?;

    let resp =
        match dev.close_session(sess_id as u32) {
            Ok(()) => VIRTIO_CRYPTO_OK as u8,
            Err(_) => VIRTIO_CRYPTO_ERR as u8,
        };

    memory.write_obj(resp, status_addr).map_err(Error::GuestMemory)?;
    Ok(1)
}

fn read_from_chain<'a>(
    memory: &GuestMemoryMmap,
    desc: DescriptorChain<'a>,
    data: &mut[u8],
    data_len: u32
) -> Result<DescriptorChain<'a>> {
    let mut offset: u32 = 0;
    let mut next = desc;

    loop {
        if next.is_write_only() {
            return Err(Error::UnexpectedWriteOnlyDescriptor);
        }

        let end = offset + next.len;
        memory.read_slice(&mut data[offset as usize..end as usize], next.addr)
            .map_err(Error::GuestMemory)?;
        if end == data_len {
            return Ok(next);
        }

        offset = end;
        next = next
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)?;
    }
}

fn write_to_chain<'a>(
    memory: &GuestMemoryMmap,
    desc: DescriptorChain<'a>,
    data: &[u8],
    data_len: u32,
) -> Result<DescriptorChain<'a>> {
    let mut offset: u32 = 0;
    let mut next = desc;

    loop {
        if !next.is_write_only() {
            return Err(Error::UnexpectedReadOnlyDescriptor);
        }

        let end = offset + next.len;
        memory.write_slice(&data[offset as usize..end as usize], next.addr)
            .map_err(Error::GuestMemory)?;
        if end == data_len {
            return Ok(next);
        }

        offset = end;
        next = next
            .next_descriptor()
            .ok_or(Error::DescriptorChainTooShort)?;
    }
}

pub fn cipher_session_op(
    memory: &GuestMemoryMmap,
    vlf_desc: DescriptorChain,
    session_id: u64,
    op: u32,
    sym_header: SymDataRequest,
    dev: &Crypto,
) -> Result<u32> {
    match sym_header.op_type {
        VIRTIO_CRYPTO_OP_ENCRYPT => {
            let mut creq = CipherDataRequest::default();
            let creq_bytes = creq.as_mut_slice();
            let creq_len = creq_bytes.len();
            creq_bytes.copy_from_slice(&sym_header.op_flf[..creq_len]);

            let mut iv = vec![0u8; creq.iv_len as usize];
            let last_desc =
                read_from_chain(
                    memory,
                    vlf_desc,
                    &mut iv,
                    creq.iv_len
                )?;

            let src_desc = next_read_descriptor(&last_desc)?;
            let mut src_data = vec![0u8; creq.src_data_len as usize];
            let last_desc =
                read_from_chain(
                    memory,
                    src_desc,
                    &mut src_data,
                    creq.src_data_len
                )?;

            let mut dst_data = vec![0u8; creq.dst_data_len as usize];
            let mut op = crypt_op {
                ses: session_id as u32,
                op: op as u16,
                flags: 0,
                len: creq.dst_data_len,
                src: src_data.as_mut_ptr(),
                dst: dst_data.as_mut_ptr(),
                mac: ptr::null_mut(),
                iv: iv.as_mut_ptr(),
            };

            let status =
                match dev.crypto_op(&mut op) {
                    Ok(()) => VIRTIO_CRYPTO_OK,
                    Err(_) => VIRTIO_CRYPTO_ERR,
                };

            let dst_desc = next_write_descriptor(&last_desc)?;
            let last_desc =
                write_to_chain(
                    memory,
                    dst_desc,
                    &dst_data,
                    creq.dst_data_len
                )?;

            let status_desc = next_write_descriptor(&last_desc)?;
            memory.write_obj(status, status_desc.addr)
                .map_err(Error::GuestMemory)?;

            return Ok(creq.dst_data_len + 1);
        }
        _ => {
            return Err(Error::UnsupportedDataQueueRequest);
        }
    }
}
