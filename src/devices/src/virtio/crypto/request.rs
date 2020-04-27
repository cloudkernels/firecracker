use std::convert::From;
use std::mem::size_of;
use std::fmt;

use vm_memory::{ByteValued, Bytes, GuestMemoryMmap, Address};
use virtio_gen::virtio_crypto::*;
use crypto_bindings::*;
use crypto_ioctls::Crypto;
use super::super::DescriptorChain;

use crate::virtio::crypto::{Result, Error};
use crate::virtio::crypto::cipher::*;

/// Available cryptographic services
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CryptoService {
    CIPHER,
    HASH,
    MAC,
    AEAD,
    Unsupported(u32),
}

impl From<u32> for CryptoService {
    fn from(value: u32) -> Self {
        match value {
            VIRTIO_CRYPTO_SERVICE_CIPHER => CryptoService::CIPHER,
            VIRTIO_CRYPTO_SERVICE_HASH => CryptoService::HASH,
            VIRTIO_CRYPTO_SERVICE_MAC => CryptoService::MAC,
            VIRTIO_CRYPTO_SERVICE_AEAD => CryptoService::AEAD,
            t => CryptoService::Unsupported(t),
        }
    }
}

impl fmt::Display for CryptoService {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptoService::CIPHER => write!(f, "cipher"),
            CryptoService::HASH => write!(f, "hash"),
            CryptoService::MAC => write!(f, "MAC"),
            CryptoService::AEAD => write!(f, "AEAD"),
            CryptoService::Unsupported(t) => write!(f, "unsupported({})", t),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum CryptoSessionOp {
    Encrypt(CryptoService),
    Decrypt(CryptoService),
    Create(CryptoService),
    Destroy(CryptoService),
}

impl From<u32> for CryptoSessionOp {
    fn from(value: u32) -> Self {
        let service = CryptoService::from(value >> 8);
        match value & 0x3 {
            0x00 => CryptoSessionOp::Encrypt(service),
            0x01 => CryptoSessionOp::Decrypt(service),
            0x02 => CryptoSessionOp::Create(service),
            0x03 => CryptoSessionOp::Destroy(service),
            _ => unreachable!(), 
        }
    }
}

/// Response type that we send back to the front-end driver
/// for "create session" requests
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct CreateSessionResponse {
    pub session_id: u64,
    pub status: u32,
    pub padding: u32,
}

unsafe impl ByteValued for CreateSessionResponse {}

pub(crate) fn next_write_descriptor<'a>(
    curr: &DescriptorChain<'a>
) -> Result<DescriptorChain<'a>> {
    let ret = curr
        .next_descriptor()
        .ok_or(Error::DescriptorChainTooShort)?;

    if !ret.is_write_only() {
        Err(Error::UnexpectedReadOnlyDescriptor)
    } else {
        Ok(ret)
    }
}

pub(crate) fn next_read_descriptor<'a>(
    curr: &DescriptorChain<'a>
) -> Result<DescriptorChain<'a>> {
    let ret = curr
        .next_descriptor()
        .ok_or(Error::DescriptorChainTooShort)?;

    if ret.is_write_only() {
        Err(Error::UnexpectedWriteOnlyDescriptor)
    } else {
        Ok(ret)
    }
}

/// The header of a data queue request as we receive it from the
/// front end driver
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct DataRequestHeader {
    pub opcode: u32,
    pub algo: u32,
    pub session: u64,
    pub flag: u32,
    padding: u32,
}

unsafe impl ByteValued for DataRequestHeader {}

pub fn handle_dataq_request(
    avail_desc: &DescriptorChain,
    mem: &GuestMemoryMmap,
    dev: &Crypto,
) -> Result<u32> {
    // We MUST be able to read the header
    if avail_desc.is_write_only() {
        return Err(Error::UnexpectedWriteOnlyDescriptor);
    }

    // Parse the data request header from guest memory
    let header = mem.read_obj::<DataRequestHeader>(avail_desc.addr)
        .map_err(Error::GuestMemory)?;

    let flf_addr = avail_desc.addr
        .checked_add(size_of::<DataRequestHeader>() as u64)
        .ok_or(Error::MalformedDataQueueRequest)?;

    let vlf_desc = next_read_descriptor(&avail_desc)?;

    match CryptoSessionOp::from(header.opcode) {
        CryptoSessionOp::Encrypt(CryptoService::CIPHER) => {
            let cipher_hdr: SymDataRequest =
                mem.read_obj(flf_addr).map_err(Error::GuestMemory)?;

            return cipher_session_op(
                mem,
                vlf_desc,
                header.session,
                COP_ENCRYPT,
                cipher_hdr,
                &dev
            );
        }
        CryptoSessionOp::Decrypt(CryptoService::CIPHER) => {
            let cipher_hdr: SymDataRequest =
                mem.read_obj(flf_addr).map_err(Error::GuestMemory)?;

            return cipher_session_op(
                mem,
                vlf_desc,
                header.session,
                COP_DECRYPT,
                cipher_hdr,
                &dev
            );
        }
        _ => {
            // Find last descriptor. Status should be ther
            let mut status_desc = vlf_desc
                .next_descriptor()
                .ok_or(Error::DescriptorChainTooShort)?;

            while status_desc.has_next() {
                status_desc = status_desc.next_descriptor().unwrap()
            }

            if !status_desc.is_write_only() {
                return Err(Error::UnexpectedReadOnlyDescriptor);
            }

            let status = VIRTIO_CRYPTO_NOTSUPP as u8;

            mem.write_obj(status, status_desc.addr)
                .map_err(Error::GuestMemory)?;

            return Ok(1);
        }
    }
}

/// The header of a control queue request as we receive it from the
/// front end driver
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct ControlRequestHeader {
    pub opcode: u32,
    pub algo: u32,
    pub flag: u32,
    _reserved: u32,
}

unsafe impl ByteValued for ControlRequestHeader {}

pub fn handle_controlq_request(
    avail_desc: &DescriptorChain,
    mem: &GuestMemoryMmap,
    dev: &Crypto,
) -> Result<u32> {
    // We MUST be able to read the header
    if avail_desc.is_write_only() {
        return Err(Error::UnexpectedWriteOnlyDescriptor);
    }

    // Parse the control request header from guest memory
    let header = mem.read_obj::<ControlRequestHeader>(avail_desc.addr)
        .map_err(Error::GuestMemory)?;

    // All operations should have a valid address that holds
    // the flf data
    let flf_addr = avail_desc.addr
        .checked_add(size_of::<ControlRequestHeader>() as u64)
        .ok_or(Error::MalformedControlQueueRequest)?;

    match CryptoSessionOp::from(header.opcode) {
        // Create a session
        CryptoSessionOp::Create(service) => {
            let vlf_desc = next_read_descriptor(&avail_desc)?;
            let status_desc = next_write_descriptor(&vlf_desc)?;

            match service {
                CryptoService::CIPHER => {
                    return create_cipher_session(
                        mem,
                        flf_addr,
                        vlf_desc.addr,
                        status_desc.addr,
                        dev
                    );
                }
                _ => {
                    let status = CreateSessionResponse {
                        session_id: 0,
                        status: VIRTIO_CRYPTO_NOTSUPP,
                        padding: 0,
                    };

                    mem.write_obj(status, status_desc.addr)
                        .map_err(Error::GuestMemory)?;
                    return Ok(size_of::<CreateSessionResponse>() as u32)
                }
            }
        }
        // Destroy a session
        CryptoSessionOp::Destroy(_) => {
            // Destroy session request has the same format in all
            // cases.
            let status_desc = next_write_descriptor(&avail_desc)?;
            return destroy_cipher_session(mem, flf_addr, status_desc.addr, dev);
        }
        _ => {
            // Find last descriptor. Status should be there
            let mut status_desc = avail_desc
                .next_descriptor()
                .ok_or(Error::DescriptorChainTooShort)?;

            while status_desc.has_next() {
                status_desc = status_desc.next_descriptor().unwrap()
            }

            if !status_desc.is_write_only() {
                return Err(Error::UnexpectedReadOnlyDescriptor);
            }

            let status = CreateSessionResponse {
                session_id: 0,
                status: VIRTIO_CRYPTO_NOTSUPP,
                padding: 0,
            };

            mem.write_obj(status, status_desc.addr)
                .map_err(Error::GuestMemory)?;

            return Ok(size_of::<CreateSessionResponse>() as u32)
        }
    }
}
