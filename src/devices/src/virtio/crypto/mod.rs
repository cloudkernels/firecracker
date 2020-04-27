use std::{io, result};

pub mod device;
pub mod event_handler;
pub mod request;

pub use self::device::Crypto;
pub use self::request::*;

use vm_memory::GuestMemoryError;

pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];
pub const VIRTIO_CRYPTO_SYM_SESS_OP_SPEC_HDR_SIZE: usize = 48;
pub const VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE: usize = 40;

#[derive(Debug)]
pub enum Error {
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// EventFd
    EventFd(io::Error),
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Unsupported queue request
    UnsupportedQueueRequest,
    /// Malformed queue request
    MalformedQueueRequest,
    /// vaccel RT error
    VaccelRuntime,
}

pub type Result<T> = result::Result<T, Error>;
