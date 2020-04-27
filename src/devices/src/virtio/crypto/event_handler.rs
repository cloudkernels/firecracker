use std::os::unix::io::AsRawFd;

use event_manager::{EventOps, Events, MutEventSubscriber};
use logger::{debug, error, warn};
use utils::epoll::EventSet;

use crate::virtio::crypto::device::Crypto;
use crate::virtio::VirtioDevice;

impl Crypto {
    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(e) = ops.add(Events::new(&self.queue_evts[0], EventSet::IN)) {
            error!("Failed to register data queue with event manager: {}", e);
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(e) = ops.add(Events::new(&self.activate_evt, EventSet::IN)) {
            error!("Failed to register activate event: {}", e);
        }
    }

    fn process_activate_event(&self, ops: &mut EventOps) {
        debug!("vAccel: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume vAccel activate event: {:?}", e);
        }
        self.register_activate_event(ops);
        if let Err(e) = ops.remove(Events::new(&self.activate_evt, EventSet::IN)) {
            error!("Failed to un-register activate event: {}", e);
        }
    }
}

impl MutEventSubscriber for Crypto {
    // Handle an event for queue
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();

        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!(
                "vAccel received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if self.is_activated() {
            let queue_evt = self.queue_evts[0].as_raw_fd();
            let activate_fd = self.activate_evt.as_raw_fd();

            match source {
                _ if queue_evt == source => self.process_queue_event(),
                _ if activate_fd == source => self.process_activate_event(ops),
                _ => warn!("vAccel: Spurious event received: {:?}", source),
            }
        } else {
            warn!(
                "vAccel: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        // This function can be called during different points in the device lifetime:
        //  - shortly after device creation,
        //  - on device activation (is-activated already true at this point),
        //  - on device restore from snapshot.
        if self.is_activated() {
            self.register_runtime_events(ops);
        } else {
            self.register_activate_event(ops);
        }
    }
}
