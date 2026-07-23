use crate::cli::XdsArgs;
use crate::db::entities::{node, policy_version};
use crate::{firewall, security};
use anyhow::{Context, Result};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::{net::SocketAddr, time::Duration};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataMap;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status, Streaming};
use tracing::{info, warn};

pub mod proto {
    tonic::include_proto!("xdp_firewall.xds.v1");
}

use proto::firewall_xds_client::FirewallXdsClient;
use proto::firewall_xds_server::{FirewallXds, FirewallXdsServer};
use proto::{
    FetchPolicyRequest, FetchPolicyResponse, HeartbeatRequest, HeartbeatResponse, PolicyUpdate,
    StreamPolicyRequest,
};

#[derive(Clone)]
pub struct XdsClientConfig {
    pub control_url: String,
    pub agent_token: Option<String>,
}

#[derive(Clone)]
pub struct XdsClient {
    inner: FirewallXdsClient<Channel>,
    agent_token: Option<String>,
}

#[derive(Clone)]
struct XdsService {
    db: DatabaseConnection,
    agent_token: Option<String>,
    push_interval: Duration,
}

pub async fn serve(db: DatabaseConnection, args: XdsArgs) -> Result<()> {
    let bind: SocketAddr = args
        .bind
        .parse()
        .with_context(|| format!("invalid xDS bind address '{}'", args.bind))?;
    let agent_token = args.agent_token.filter(|token| !token.trim().is_empty());
    let push_interval = Duration::from_secs(args.push_interval_seconds.max(1));
    info!(
        %bind,
        auth_enabled = agent_token.is_some(),
        push_interval_seconds = push_interval.as_secs(),
        "xDS gRPC server listening"
    );
    Server::builder()
        .add_service(FirewallXdsServer::new(XdsService {
            db,
            agent_token,
            push_interval,
        }))
        .serve(bind)
        .await
        .context("xDS gRPC server failed")
}

impl XdsClient {
    pub async fn connect(config: XdsClientConfig) -> Result<Self> {
        let inner = FirewallXdsClient::connect(config.control_url.clone())
            .await
            .with_context(|| {
                format!("failed to connect xDS control plane {}", config.control_url)
            })?;
        Ok(Self {
            inner,
            agent_token: config.agent_token.filter(|token| !token.trim().is_empty()),
        })
    }

    pub async fn fetch_policy(
        &mut self,
        node_id: &str,
        interface_name: &str,
        current_version: i64,
    ) -> Result<Option<(i64, firewall::PolicySnapshot)>> {
        let request = self.with_auth(FetchPolicyRequest {
            node_id: node_id.to_string(),
            interface_name: interface_name.to_string(),
            current_version,
        })?;
        let response = self.inner.fetch_policy(request).await?.into_inner();
        if response.unchanged {
            return Ok(None);
        }
        let snapshot = serde_json::from_str(&response.policy_json)
            .context("xDS control plane returned invalid policy JSON")?;
        Ok(Some((response.version, snapshot)))
    }

    pub async fn stream_policy(
        &mut self,
        node_id: &str,
        interface_name: &str,
        current_version: i64,
    ) -> Result<Streaming<PolicyUpdate>> {
        let request = self.with_auth(StreamPolicyRequest {
            node_id: node_id.to_string(),
            interface_name: interface_name.to_string(),
            current_version,
        })?;
        Ok(self.inner.stream_policy(request).await?.into_inner())
    }

    pub fn policy_from_update(update: PolicyUpdate) -> Result<(i64, firewall::PolicySnapshot)> {
        let snapshot = serde_json::from_str(&update.policy_json)
            .context("xDS control plane returned invalid policy JSON")?;
        Ok((update.version, snapshot))
    }

    pub async fn report_heartbeat(
        &mut self,
        node_id: &str,
        interface_name: &str,
        last_applied_version: i64,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let request = self.with_auth(HeartbeatRequest {
            node_id: node_id.to_string(),
            interface_name: interface_name.to_string(),
            last_applied_version,
            status: status.to_string(),
            error: error.unwrap_or_default().to_string(),
        })?;
        self.inner.report_heartbeat(request).await?;
        Ok(())
    }

    fn with_auth<T>(&self, message: T) -> Result<Request<T>> {
        let mut request = Request::new(message);
        if let Some(token) = self.agent_token.as_deref() {
            let bearer = format!("Bearer {token}");
            request.metadata_mut().insert(
                "authorization",
                bearer
                    .parse()
                    .context("failed to build xDS authorization metadata")?,
            );
            request.metadata_mut().insert(
                "x-agent-token",
                token
                    .parse()
                    .context("failed to build xDS token metadata")?,
            );
        }
        Ok(request)
    }
}

#[tonic::async_trait]
impl FirewallXds for XdsService {
    type StreamPolicyStream = ReceiverStream<std::result::Result<PolicyUpdate, Status>>;

    async fn fetch_policy(
        &self,
        request: Request<FetchPolicyRequest>,
    ) -> std::result::Result<Response<FetchPolicyResponse>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(unauthenticated_status());
        }
        let request = request.into_inner();
        let version = latest_version(&self.db).await.map_err(internal_status)?;
        if version <= request.current_version {
            return Ok(Response::new(FetchPolicyResponse {
                version,
                unchanged: true,
                policy_json: String::new(),
            }));
        }

        let snapshot = firewall::load_policy(&self.db, firewall::DEFAULT_POLICY_NAME)
            .await
            .map_err(internal_status)?;
        let policy_json = serde_json::to_string(&snapshot).map_err(internal_status)?;
        info!(
            node_id = %request.node_id,
            interface = %request.interface_name,
            requested_version = request.current_version,
            version,
            "xDS returned updated policy"
        );
        Ok(Response::new(FetchPolicyResponse {
            version,
            unchanged: false,
            policy_json,
        }))
    }

    async fn stream_policy(
        &self,
        request: Request<StreamPolicyRequest>,
    ) -> std::result::Result<Response<Self::StreamPolicyStream>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(unauthenticated_status());
        }
        let request = request.into_inner();
        let db = self.db.clone();
        let interval = self.push_interval;
        let (tx, rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let mut sent_version = request.current_version;
            loop {
                match policy_update(&db, sent_version).await {
                    Ok(Some(update)) => {
                        sent_version = update.version;
                        info!(
                            node_id = %request.node_id,
                            interface = %request.interface_name,
                            version = sent_version,
                            "xDS pushed updated policy"
                        );
                        if tx.send(Ok(update)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        let _ = tx.send(Err(internal_status(err))).await;
                        break;
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn report_heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> std::result::Result<Response<HeartbeatResponse>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(unauthenticated_status());
        }
        let request = request.into_inner();
        upsert_heartbeat(&self.db, request)
            .await
            .map_err(internal_status)?;
        Ok(Response::new(HeartbeatResponse { accepted: true }))
    }
}

impl XdsService {
    fn authorized(&self, metadata: &MetadataMap) -> bool {
        let Some(expected) = self.agent_token.as_deref() else {
            return true;
        };
        if metadata_token(metadata).is_some_and(|token| token == expected) {
            return true;
        }
        warn!("missing or invalid xDS agent token");
        false
    }
}

fn metadata_token(metadata: &MetadataMap) -> Option<&str> {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            metadata
                .get("x-agent-token")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
}

async fn latest_version(db: &DatabaseConnection) -> Result<i64> {
    Ok(policy_version::Entity::find()
        .filter(policy_version::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .one(db)
        .await?
        .map_or(0, |row| row.version))
}

async fn policy_update(
    db: &DatabaseConnection,
    current_version: i64,
) -> Result<Option<PolicyUpdate>> {
    let version = latest_version(db).await?;
    if version <= current_version {
        return Ok(None);
    }
    let snapshot = firewall::load_policy(db, firewall::DEFAULT_POLICY_NAME).await?;
    let policy_json = serde_json::to_string(&snapshot)?;
    Ok(Some(PolicyUpdate {
        version,
        policy_json,
    }))
}

async fn upsert_heartbeat(db: &DatabaseConnection, request: HeartbeatRequest) -> Result<()> {
    let now = chrono::Utc::now().naive_utc();
    let public_error = if request.error.trim().is_empty() {
        None
    } else {
        Some(security::public_error_message(&request.error))
    };
    if let Some(row) = node::Entity::find_by_id(request.node_id.clone())
        .one(db)
        .await?
    {
        let mut active: node::ActiveModel = row.into();
        active.policy_name = Set(firewall::DEFAULT_POLICY_NAME.to_string());
        active.interface_name = Set(request.interface_name);
        active.last_seen_at = Set(now);
        active.last_applied_version = Set(request.last_applied_version);
        active.status = Set(request.status);
        active.error = Set(public_error);
        active.update(db).await?;
    } else {
        node::ActiveModel {
            node_id: Set(request.node_id),
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            interface_name: Set(request.interface_name),
            last_seen_at: Set(now),
            last_applied_version: Set(request.last_applied_version),
            status: Set(request.status),
            error: Set(public_error),
        }
        .insert(db)
        .await?;
    }
    Ok(())
}

fn internal_status(error: impl std::fmt::Display) -> Status {
    Status::internal(error.to_string())
}

fn unauthenticated_status() -> Status {
    Status::unauthenticated("missing or invalid xDS agent token")
}
