use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::watch;

pub(super) struct DropSubscriptionRegistry {
    subscriptions: Mutex<HashMap<Option<String>, usize>>,
    change_version: AtomicU64,
    changes_tx: watch::Sender<u64>,
}

impl DropSubscriptionRegistry {
    pub(super) fn new() -> Self {
        let (changes_tx, _) = watch::channel(0);
        Self {
            subscriptions: Mutex::new(HashMap::new()),
            change_version: AtomicU64::new(0),
            changes_tx,
        }
    }

    pub(super) fn add(&self, node_id: Option<String>) -> Option<String> {
        let node_id = normalize_drop_node_filter(node_id);
        {
            let mut subscriptions = self
                .subscriptions
                .lock()
                .expect("drop event subscription mutex poisoned");
            *subscriptions.entry(node_id.clone()).or_insert(0) += 1;
        }
        self.notify_changed();
        node_id
    }

    pub(super) fn remove(&self, node_id: &Option<String>) {
        {
            let mut subscriptions = self
                .subscriptions
                .lock()
                .expect("drop event subscription mutex poisoned");
            if let Some(count) = subscriptions.get_mut(node_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    subscriptions.remove(node_id);
                }
            }
        }
        self.notify_changed();
    }

    pub(super) fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.changes_tx.subscribe()
    }

    pub(super) fn enabled_for_node(&self, node_id: &str) -> bool {
        let subscriptions = self
            .subscriptions
            .lock()
            .expect("drop event subscription mutex poisoned");
        subscriptions.get(&None).copied().unwrap_or_default() > 0
            || subscriptions
                .get(&Some(node_id.to_string()))
                .copied()
                .unwrap_or_default()
                > 0
    }

    fn notify_changed(&self) {
        let version = self.change_version.fetch_add(1, Ordering::SeqCst) + 1;
        self.changes_tx.send_replace(version);
    }
}

fn normalize_drop_node_filter(node_id: Option<String>) -> Option<String> {
    node_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("all"))
}
