use std::{io, result};

pub mod device;
pub mod event_handler;

pub use self::device::Crypto;

use vm_memory::GuestMemoryError;
use vmm_sys_util::errno;

pub const QUEUE_SIZE: u16 = 1024;

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

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::EventFd(err)
    }
}

pub type Result<T> = result::Result<T, Error>;
