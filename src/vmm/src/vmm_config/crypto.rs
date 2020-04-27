use std::fmt::{Display, Formatter};
use std::result;
use std::sync::{Arc, Mutex};

use devices::virtio::Crypto;

type Result<T> = result::Result<T, CryptoError>;

/// Errors related with CryptoDeviceConfig
#[derive(Debug)]
pub enum CryptoError {
    /// Could not create device
    CreateCryptoDevice(devices::virtio::crypto::Error),
}

/// Configuration of a crypto device
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CryptoDeviceConfig {
    /// Unique identifier of the device.
    pub crypto_dev_id: String,
    /// Path of the host device.
    pub host_crypto_dev: String,
}

/// Builder object for creating crypto devices in the guest
#[derive(Default)]
pub struct CryptoBuilder {
    /// List of crypto devices
    pub list: Vec<Arc<Mutex<Crypto>>>,
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::CryptoError::*;
        match *self {
            CreateCryptoDevice(ref e) => write!(
                f,
                "Unable to create Crypto device {:?}",
                e
            ),
        }
    }
}

impl CryptoBuilder {
    /// Constructor of crypto devices. It initializes an empty list
    pub fn new() -> Self {
        Self {
            list: Vec::<Arc<Mutex<Crypto>>>::new(),
        }
    }

    /// Find a device in the builder's list and return its position
    pub fn find_device(&self, dev_id: &str) -> Option<usize> {
        self.list
            .iter()
            .position(|crypto| crypto.lock().unwrap().id().eq(dev_id))
    }

    /// Create a new Crypto device from CryptoDeviceConfig and add it to the
    /// crypto devices list. 
    pub fn insert(&mut self, cfg: CryptoDeviceConfig) -> Result<()> {
        let position = self.find_device(&cfg.crypto_dev_id);
        let crypto_dev = Arc::new(Mutex::new(Self::create_crypto(cfg)?));

        match position {
            // New device
            None => {
                self.list.push(crypto_dev);
            }
            // Update existing device
            Some(index) => {
                self.list[index] = crypto_dev;
            }
        }

        Ok(())
    }

    /// Create a new Crypto device from CryptoDeviceConfig
    pub fn create_crypto(cfg: CryptoDeviceConfig) -> Result<Crypto> {
        devices::virtio::crypto::Crypto::new(
            cfg.crypto_dev_id,
            cfg.host_crypto_dev,
        )
        .map_err(CryptoError::CreateCryptoDevice)
    }
}
