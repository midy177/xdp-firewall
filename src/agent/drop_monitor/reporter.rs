use crate::{agent::monitor, cli::AgentArgs, control_plane::xds};
use std::path::PathBuf;
use tokio::time::Duration;
use tracing::error;

pub(super) fn spawn_reporter(
    args: &AgentArgs,
    node_id: &str,
    interface: &str,
    events_path: PathBuf,
) -> tokio::task::JoinHandle<()> {
    let client_config = xds::XdsClientConfig {
        control_url: args.control_url.clone(),
        agent_token: args.agent_token.clone(),
        tls: xds::XdsClientTls::from(&args.xds_tls),
    };
    let node_id = node_id.to_string();
    let interface = interface.to_string();
    tokio::spawn(async move {
        run_reporter(client_config, node_id, interface, events_path).await;
    })
}

async fn run_reporter(
    client_config: xds::XdsClientConfig,
    node_id: String,
    interface: String,
    events_path: PathBuf,
) {
    loop {
        report_until_disconnect(&client_config, &node_id, &interface, events_path.clone()).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn report_until_disconnect(
    client_config: &xds::XdsClientConfig,
    node_id: &str,
    interface: &str,
    events_path: PathBuf,
) {
    match xds::XdsClient::connect(client_config.clone()).await {
        Ok(mut client) => report_events(&mut client, node_id, interface, events_path).await,
        Err(err) => {
            error!(error = %err, "failed to connect xDS for drop events; reconnecting");
        }
    }
}

async fn report_events(
    client: &mut xds::XdsClient,
    node_id: &str,
    interface: &str,
    events_path: PathBuf,
) {
    let events = match monitor::spawn_drop_event_reader(events_path) {
        Ok(events) => events,
        Err(err) => {
            error!(
                error = %err,
                "failed to open XDP drop event reader; reconnecting"
            );
            return;
        }
    };
    if let Err(err) = client
        .report_drop_events(node_id.to_string(), interface.to_string(), events)
        .await
    {
        error!(error = %err, "failed to report xDS drop events; reconnecting");
    }
}
