use crate::virtio::crypto::Error;
use crate::virtio::crypto::Result;
use crate::virtio::crypto::QUEUE_SIZE;
use crate::virtio::{
    ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_RNG, VIRTIO_MMIO_INT_VRING
};

use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::fs::File;
use std::path::Path;
use utils::eventfd::EventFd;

use vm_memory::{Bytes, GuestMemoryMmap};

use crate::Error as DeviceError;

pub struct Crypto {
    pub(crate) id: String,
    pub(crate) host_dev: String,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    pub(crate) device_state: DeviceState,
}


impl Crypto {
    pub fn new(id: String, host_dev: String) -> Result<Self> {
        let queues = vec![Queue::new(QUEUE_SIZE)];
        let queue_evts = vec![EventFd::new(libc::EFD_NONBLOCK)?];

        Ok(Crypto {
            id,
            host_dev,
            avail_features: 0u64,
            acked_features: 0u64,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            queues,
            queue_evts,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            device_state: DeviceState::Inactive,
        })
    }

    pub fn id(&self) -> &String {
        &self.id
    }

    pub(crate) fn process_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[0].read() {
            error!("crypto: failed to get control queue event: {:?}", e);
        } else {
            self.process_queue();
        }
    }

    pub(crate) fn process_queue(&mut self) {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            DeviceState::Inactive => unreachable!(),
        };

        let queue = &mut self.queues[0];
        while let Some(head) = queue.pop(mem) {
            debug!("rng: reading {} random bytes from host", head.len);
            mem.read_from(
                head.addr,
                &mut File::open(Path::new(&self.host_dev)).unwrap(),
                head.len as usize
            ).expect("rng: Could not read from device");

            queue.add_used(mem, head.index, head.len);
        }

        let _ = self.signal_used_queue();
    }

    pub(crate) fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);

        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            DeviceError::FailedSignalingUsedQueue(e)
        })?;
        Ok(())
    }
}

impl VirtioDevice for Crypto {
    fn device_type(&self) -> u32 {
        TYPE_RNG
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    /// Returns the current device interrupt status.
    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        info!("crypto: driver acked features: {:?}", acked_features);
        self.acked_features = acked_features;
    }

    fn read_config(&self, _offset: u64, mut _data: &mut [u8]) {
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            error!("Crypte: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}
