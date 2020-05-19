use std::os::unix::io::AsRawFd;

use logger::{error, warn};
use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::crypto::device::Crypto;
use crate::virtio::VirtioDevice;

impl Crypto {
    fn process_activate_event(&self, event_manager: &mut EventManager) {
        let self_subscriber = event_manager
            .subscriber(self.activate_evt.as_raw_fd())
            .unwrap();

        event_manager
            .register(
                self.queue_evts[0].as_raw_fd(),
                EpollEvent::new(EventSet::IN, self.queue_evts[0].as_raw_fd() as u64),
                self_subscriber.clone(),
            )
            .unwrap_or_else(|e| {
                error!(
                    "Failed to register crypto data queue with event manager: {:?}",
                    e
                );
            });

        event_manager
            .unregister(self.activate_evt.as_raw_fd())
            .unwrap_or_else(|e| {
                error!("Failed to unregister crypto activate evt: {:?}", e);
            })
    }
}

impl Subscriber for Crypto {
    // handle an event for queue
    fn process(&mut self, event: &EpollEvent, evmgr: &mut EventManager) {
        let source = event.fd();
        let event_set = event.event_set();

        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!(
                "Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if self.is_activated() {
            let vq_event = self.queue_evts[0].as_raw_fd();
            let activate_fd = self.activate_evt.as_raw_fd();

            match source {
                _ if vq_event == source => self.process_queue_event(),
                _ if activate_fd == source => self.process_activate_event(evmgr),
                _ => warn!("Crypto: Spurious event received: {:?}", source),
            }
        } else {
            warn!(
                "Crypto: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.activate_evt.as_raw_fd() as u64,
        )]
    }
}
