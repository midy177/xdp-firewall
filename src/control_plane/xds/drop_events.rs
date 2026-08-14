use serde::Serialize;
use std::sync::Arc;
use tokio::sync::broadcast;

mod report;
mod subscriptions;

pub(super) use report::accept_reported_drop_events;
use subscriptions::DropSubscriptionRegistry;

#[derive(Debug, Clone, Serialize)]
pub struct DropEventView {
    pub node_id: String,
    pub interface_name: String,
    pub time: String,
    pub event_time_ns: u64,
    pub cpu: u32,
    pub reason: String,
    pub src: String,
    pub family: u32,
    pub proto: String,
    pub dport: u32,
    pub country: Option<String>,
    pub threat_source: Option<String>,
    pub action: String,
}

#[derive(Clone)]
pub struct DropEventHub {
    inner: Arc<DropEventHubInner>,
}

struct DropEventHubInner {
    sender: broadcast::Sender<DropEventView>,
    subscriptions: DropSubscriptionRegistry,
}

pub struct DropEventSubscription {
    hub: DropEventHub,
    receiver: broadcast::Receiver<DropEventView>,
    node_id: Option<String>,
}

impl DropEventHub {
    #[must_use]
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(4096);
        Self {
            inner: Arc::new(DropEventHubInner {
                sender,
                subscriptions: DropSubscriptionRegistry::new(),
            }),
        }
    }

    #[must_use]
    pub fn subscribe(&self, node_id: Option<String>) -> DropEventSubscription {
        let node_id = self.inner.subscriptions.add(node_id);
        DropEventSubscription {
            hub: self.clone(),
            receiver: self.inner.sender.subscribe(),
            node_id,
        }
    }

    pub(super) fn publish(&self, event: DropEventView) {
        let _ = self.inner.sender.send(event);
    }

    pub(super) fn subscribe_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.subscriptions.subscribe_changes()
    }

    pub(super) fn enabled_for_node(&self, node_id: &str) -> bool {
        self.inner.subscriptions.enabled_for_node(node_id)
    }
}

impl Default for DropEventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl DropEventSubscription {
    pub async fn recv(&mut self) -> Option<DropEventView> {
        loop {
            match self.receiver.recv().await {
                Ok(event) => {
                    if self
                        .node_id
                        .as_deref()
                        .is_none_or(|node_id| event.node_id == node_id)
                    {
                        return Some(event);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl Drop for DropEventSubscription {
    fn drop(&mut self) {
        self.hub.inner.subscriptions.remove(&self.node_id);
    }
}
