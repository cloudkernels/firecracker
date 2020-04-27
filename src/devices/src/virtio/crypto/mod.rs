use std::{io, result};

pub mod device;
pub mod event_handler;
pub mod request;
pub mod cipher;

pub use self::device::Crypto;
pub use self::request::*;

use vm_memory::GuestMemoryError;
use vmm_sys_util::errno;

pub const QUEUE_SIZE: u16 = 1024;
pub const NUM_QUEUES: usize = 2;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];
pub const VIRTIO_CRYPTO_SYM_SESS_OP_SPEC_HDR_SIZE: usize = 48;
pub const VIRTIO_CRYPTO_SYM_DATA_REQ_HDR_SIZE: usize = 40;

/* Data queue used for crypto operations */
pub const DATAQ_INDEX: usize = 0;

/* Control queue used for session management */
pub const CONTROLQ_INDEX: usize = 1;

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
    /// Unsupported control queue request
    UnsupportedControlQueueRequest,
    /// Malformed control queue request
    MalformedControlQueueRequest,
    /// Unsupported data queue request
    UnsupportedDataQueueRequest,
    /// Malformed data queue request
    MalformedDataQueueRequest,
    /// Error while interacting with the host device
    HostDev(errno::Error),
}

impl From<errno::Error> for Error {
    fn from(errno: errno::Error) -> Self {
        Error::HostDev(errno)
    }
}

pub type Result<T> = result::Result<T, Error>;
