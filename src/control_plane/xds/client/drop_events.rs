use super::super::proto::DropEvent;
use super::XdsClient;
use crate::agent::monitor;
use anyhow::Result;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

impl XdsClient {
    pub async fn report_drop_events(
        &mut self,
        node_id: String,
        interface_name: String,
        mut events: monitor::DropEventReader,
    ) -> Result<()> {
        let (tx, rx) = mpsc::channel(1024);
        let forwarder = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if tx
                    .send(drop_event_message(&node_id, &interface_name, event))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let request = self.with_auth(ReceiverStream::new(rx))?;
        let result = self.inner.report_drop_events(request).await;
        forwarder.abort();
        result?;
        Ok(())
    }
}

fn drop_event_message(
    node_id: &str,
    interface_name: &str,
    event: monitor::DropEventLine,
) -> DropEvent {
    DropEvent {
        node_id: node_id.to_string(),
        interface_name: interface_name.to_string(),
        time: event.time,
        event_time_ns: event.event_time_ns,
        cpu: event.cpu,
        reason: event.reason.to_string(),
        src: event.src.to_string(),
        family: u32::from(event.family),
        proto: event.proto,
        dport: u32::from(event.dport),
        country: event.country.unwrap_or_default(),
        action: event.action.to_string(),
    }
}
