use super::{ApiResult, ApiState};
use axum::{
    body::Body,
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::{convert::Infallible, time::Duration};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

#[derive(Debug, Deserialize)]
pub(super) struct DropEventQuery {
    node_id: Option<String>,
}

pub(super) async fn stream(
    Query(query): Query<DropEventQuery>,
    State(state): State<ApiState>,
) -> ApiResult<Response> {
    let node_id = query
        .node_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("all"));
    let mut subscription = state.drop_events.subscribe(node_id);
    let (tx, rx) = mpsc::channel::<std::result::Result<String, Infallible>>(256);
    tokio::spawn(async move {
        loop {
            if tx.is_closed() {
                break;
            }
            tokio::select! {
                event = subscription.recv() => {
                    let Some(event) = event else {
                        break;
                    };
                    let Ok(line) = serde_json::to_string(&event) else {
                        continue;
                    };
                    if tx.send(Ok(format!("{line}\n"))).await.is_err() {
                        break;
                    }
                }
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    });
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
        ],
        Body::from_stream(ReceiverStream::new(rx)),
    )
        .into_response())
}
