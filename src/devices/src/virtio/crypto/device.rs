use crate::virtio::crypto::Error;
use crate::virtio::crypto::Result;
use crate::virtio::crypto::{DATAQ_INDEX, CONTROLQ_INDEX, NUM_QUEUES, QUEUE_SIZES, request::*};
use crate::virtio::{
    ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_CRYPTO, VIRTIO_MMIO_INT_VRING
};

use std::io::Write;
use std::cmp;
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use utils::eventfd::EventFd;

use virtio_gen::virtio_crypto::*;
use vm_memory::{ByteValued, GuestMemoryMmap};

use crate::Error as DeviceError;

use crypto_ioctls::Crypto as HostCrypto;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConfigSpace {
    pub status: __le32,
    pub max_dataqueues: __le32,
    pub crypto_services: __le32,
    
    /* algorithms masks */
    pub cipher_algo_l: __le32,
    pub cipher_algo_h: __le32,
    pub hash_algo: __le32,
    pub mac_algo_l: __le32,
    pub mac_algo_h: __le32,
    pub aead_algo: __le32,

    /* maximum length of cipher key in bytes */
    pub max_cipher_key_len: __le32,

    /* max length of authenticated key in bytes */
    pub max_auth_key_len: __le32,

    pub reserved: __le32,

    /* Maximum size of each crypto requests's content in bytes */
    pub max_size: __le64,
}

impl Default for ConfigSpace {
    fn default() -> ConfigSpace {
        ConfigSpace {
            status: VIRTIO_CRYPTO_S_HW_READY,
            max_dataqueues: (NUM_QUEUES - 1) as u32,
            crypto_services: 1 << VIRTIO_CRYPTO_SERVICE_CIPHER,
            cipher_algo_l: 1 << VIRTIO_CRYPTO_CIPHER_AES_CBC,
            cipher_algo_h : 0,
            hash_algo: 0,
            mac_algo_l: 0,
            mac_algo_h: 0,
            aead_algo: 0,
            max_cipher_key_len: 32768,
            max_auth_key_len: 0,
            reserved: 0,
            max_size: 64*1024*1024,
        }
    }
}

unsafe impl ByteValued for ConfigSpace {}

pub struct Crypto {
    pub(crate) id: String,
    host_dev: HostCrypto,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) config_space: ConfigSpace,
    pub(crate) activate_evt: EventFd,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    pub(crate) device_state: DeviceState,
}


impl Crypto {
    pub fn new(id: String, host_device: String) -> Result<Self> {
        // Try to open the device
        let host_dev = crypto_ioctls::Crypto::new(&host_device)?;

        // No stateless atm (until I figure out what that is)
        let avail_features = 1u64 << VIRTIO_F_VERSION_1;
        
        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let mut queue_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
        }

        // TODO: Check if we need to fill up now
        let config_space = ConfigSpace::default();
        info!("Crypto device initial status: {}", config_space.status);

        Ok(Crypto {
            id,
            host_dev,
            avail_features,
            acked_features: 0u64,
            config_space,
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

    pub(crate) fn process_control_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[CONTROLQ_INDEX].read() {
            error!("crypto: failed to get control queue event: {:?}", e);
        } else {
            self.process_control_queue();
        }
    }

    pub(crate) fn process_data_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[DATAQ_INDEX].read() {
            error!("crypto: failed to get data queue event: {:?}", e);
        } else {
            self.process_data_queue();
        }
    }

    pub(crate) fn process_control_queue(&mut self) {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            DeviceState::Inactive => unreachable!(),
        };

        let queue = &mut self.queues[CONTROLQ_INDEX];
        while let Some(head) = queue.pop(mem) {
            match handle_controlq_request(&head, mem, &self.host_dev) {
                Ok(size) => {
                    queue.add_used(mem, head.index, size);
                }
                Err(e) => {
                    error!("Failed to parse available descriptor chain: {:?}", e);
                }
            }
        }

        let _ = self.signal_used_queue();
    }

    pub(crate) fn process_data_queue(&mut self) {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            DeviceState::Inactive => unreachable!(),
        };

        let queue = &mut self.queues[DATAQ_INDEX];
        while let Some(head) = queue.pop(mem) {
            match handle_dataq_request(&head, mem, &self.host_dev) {
                Ok(size) => {
                    queue.add_used(mem, head.index, size);
                }
                Err(e) => {
                    error!("Failed to handle data queue on descriptor chain: {:?}", e);
                }
            }
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
        TYPE_CRYPTO
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

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_space_bytes = self.config_space.as_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            data.write_all(
                &config_space_bytes[offset as usize..cmp::min(end, config_len) as usize],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_space_bytes = self.config_space.as_mut_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        let (_, right) = config_space_bytes.split_at_mut(offset as usize);
        right.copy_from_slice(&data[..]);
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
