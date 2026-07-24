use crate::cli::XdsArgs;
use crate::db::entities::{node, policy_version};
use crate::{firewall, k8s, monitor, security};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set, sea_query::OnConflict,
};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, broadcast, mpsc, watch};
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
    DropEvent, DropEventResponse, FetchPolicyRequest, FetchPolicyResponse, HeartbeatRequest,
    HeartbeatResponse, PolicyUpdate, StreamPolicyRequest,
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
    drop_events: DropEventHub,
    runtime_trusted_cidrs: RuntimeTrustedCidrs,
}

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
    pub action: String,
}

#[derive(Clone)]
pub struct DropEventHub {
    inner: Arc<DropEventHubInner>,
}

struct DropEventHubInner {
    sender: broadcast::Sender<DropEventView>,
    subscriptions: StdMutex<HashMap<Option<String>, usize>>,
    change_version: AtomicU64,
    changes_tx: watch::Sender<u64>,
}

pub struct DropEventSubscription {
    hub: DropEventHub,
    receiver: broadcast::Receiver<DropEventView>,
    node_id: Option<String>,
}

impl DropEventHub {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(4096);
        let (changes_tx, _) = watch::channel(0);
        Self {
            inner: Arc::new(DropEventHubInner {
                sender,
                subscriptions: StdMutex::new(HashMap::new()),
                change_version: AtomicU64::new(0),
                changes_tx,
            }),
        }
    }

    pub fn subscribe(&self, node_id: Option<String>) -> DropEventSubscription {
        let node_id = normalize_drop_node_filter(node_id);
        {
            let mut subscriptions = self
                .inner
                .subscriptions
                .lock()
                .expect("drop event subscription mutex poisoned");
            *subscriptions.entry(node_id.clone()).or_insert(0) += 1;
        }
        self.notify_changed();
        DropEventSubscription {
            hub: self.clone(),
            receiver: self.inner.sender.subscribe(),
            node_id,
        }
    }

    fn publish(&self, event: DropEventView) {
        let _ = self.inner.sender.send(event);
    }

    fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.inner.changes_tx.subscribe()
    }

    fn enabled_for_node(&self, node_id: &str) -> bool {
        let subscriptions = self
            .inner
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
        let version = self.inner.change_version.fetch_add(1, Ordering::SeqCst) + 1;
        self.inner.changes_tx.send_replace(version);
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
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl Drop for DropEventSubscription {
    fn drop(&mut self) {
        {
            let mut subscriptions = self
                .hub
                .inner
                .subscriptions
                .lock()
                .expect("drop event subscription mutex poisoned");
            if let Some(count) = subscriptions.get_mut(&self.node_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    subscriptions.remove(&self.node_id);
                }
            }
        }
        self.hub.notify_changed();
    }
}

fn normalize_drop_node_filter(node_id: Option<String>) -> Option<String> {
    node_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("all"))
}

#[derive(Clone)]
struct RuntimeTrustedCidrs {
    configured: Vec<IpNet>,
    k8s_discovery: Option<k8s::KubernetesDiscovery>,
    cache_ttl: Duration,
    cache: Arc<Mutex<K8sDiscoveryCache>>,
}

#[derive(Default)]
struct K8sDiscoveryCache {
    cidrs: Vec<IpNet>,
    fetched_at: Option<Instant>,
}

impl RuntimeTrustedCidrs {
    fn new(
        configured: Vec<IpNet>,
        k8s_discovery: Option<k8s::KubernetesDiscovery>,
        cache_ttl: Duration,
    ) -> Self {
        Self {
            configured,
            k8s_discovery,
            cache_ttl,
            cache: Arc::new(Mutex::new(K8sDiscoveryCache::default())),
        }
    }

    fn enabled(&self) -> bool {
        !self.configured.is_empty() || self.k8s_discovery.is_some()
    }

    async fn current(&self) -> Vec<IpNet> {
        let mut cidrs = Vec::new();
        let mut seen = HashSet::new();
        for cidr in &self.configured {
            if seen.insert(*cidr) {
                cidrs.push(*cidr);
            }
        }

        let Some(discovery) = self.k8s_discovery.as_ref() else {
            return cidrs;
        };
        let discovered = self.cached_k8s_cidrs(discovery).await;
        for cidr in discovered {
            if seen.insert(cidr) {
                cidrs.push(cidr);
            }
        }
        cidrs
    }

    async fn cached_k8s_cidrs(&self, discovery: &k8s::KubernetesDiscovery) -> Vec<IpNet> {
        let mut cache = self.cache.lock().await;
        if cache
            .fetched_at
            .is_some_and(|fetched_at| fetched_at.elapsed() < self.cache_ttl)
        {
            return cache.cidrs.clone();
        }

        match discovery.discover().await {
            Ok(discovered) => {
                if discovered.service_cidr_partial {
                    warn!(
                        service_entries = discovered.service_cidrs,
                        "Kubernetes ServiceCIDR API is unavailable; using existing Service ClusterIPs as partial runtime whitelist"
                    );
                }
                cache.cidrs = discovered.cidrs;
                cache.fetched_at = Some(Instant::now());
                cache.cidrs.clone()
            }
            Err(err) => {
                warn!(
                    error = %err,
                    stale_entries = cache.cidrs.len(),
                    "Kubernetes runtime address discovery failed; continuing xDS policy delivery with cached/static runtime trusted CIDRs"
                );
                cache.cidrs.clone()
            }
        }
    }
}

pub async fn serve(db: DatabaseConnection, args: XdsArgs, drop_events: DropEventHub) -> Result<()> {
    let bind: SocketAddr = args
        .bind
        .parse()
        .with_context(|| format!("invalid xDS bind address '{}'", args.bind))?;
    let agent_token = args.agent_token.filter(|token| !token.trim().is_empty());
    reject_unsafe_unauthenticated_bind(bind, agent_token.as_deref())?;
    let push_interval = Duration::from_secs(args.push_interval_seconds.max(1));
    let runtime_trusted_cidrs = normalize_runtime_trusted_cidrs(&args.trusted_cidrs)?;
    let k8s_discovery = k8s::KubernetesDiscovery::from_args(&args.k8s)?;
    let runtime_trusted_cidrs =
        RuntimeTrustedCidrs::new(runtime_trusted_cidrs, k8s_discovery, push_interval);
    info!(
        %bind,
        auth_enabled = agent_token.is_some(),
        push_interval_seconds = push_interval.as_secs(),
        runtime_trusted_cidrs = runtime_trusted_cidrs.configured.len(),
        k8s_discovery_enabled = runtime_trusted_cidrs.k8s_discovery.is_some(),
        "xDS gRPC server listening"
    );
    Server::builder()
        .add_service(FirewallXdsServer::new(XdsService {
            db,
            agent_token,
            push_interval,
            drop_events,
            runtime_trusted_cidrs,
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

    pub fn policy_from_update(
        update: PolicyUpdate,
    ) -> Result<(i64, Option<firewall::PolicySnapshot>, bool)> {
        let snapshot = if update.policy_json.trim().is_empty() {
            None
        } else {
            Some(
                serde_json::from_str(&update.policy_json)
                    .context("xDS control plane returned invalid policy JSON")?,
            )
        };
        Ok((update.version, snapshot, update.drop_monitor_enabled))
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
                    .send(DropEvent {
                        node_id: node_id.clone(),
                        interface_name: interface_name.clone(),
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
                    })
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
        if version <= request.current_version && !self.runtime_trusted_cidrs.enabled() {
            return Ok(Response::new(FetchPolicyResponse {
                version,
                unchanged: true,
                policy_json: String::new(),
            }));
        }

        let (snapshot, runtime_fingerprint) =
            load_xds_snapshot(&self.db, &self.runtime_trusted_cidrs)
                .await
                .map_err(internal_status)?;
        let policy_json = serde_json::to_string(&snapshot).map_err(internal_status)?;
        info!(
            node_id = %request.node_id,
            interface = %request.interface_name,
            requested_version = request.current_version,
            version,
            runtime_fingerprint,
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
        let drop_events = self.drop_events.clone();
        let runtime_trusted_cidrs = self.runtime_trusted_cidrs.clone();
        let mut drop_monitor_changes = drop_events.subscribe_changes();
        let (tx, rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let mut sent_version = request.current_version;
            let mut sent_runtime_fingerprint = None;
            let mut sent_drop_monitor_enabled = drop_events.enabled_for_node(&request.node_id);
            if sent_drop_monitor_enabled
                && tx
                    .try_send(Ok(PolicyUpdate {
                        version: sent_version.max(0),
                        policy_json: String::new(),
                        drop_monitor_enabled: sent_drop_monitor_enabled,
                    }))
                    .is_err()
            {
                return;
            }
            loop {
                if tx.is_closed() {
                    break;
                }
                match build_policy_update(
                    &db,
                    sent_version,
                    sent_runtime_fingerprint.as_deref(),
                    &runtime_trusted_cidrs,
                )
                .await
                {
                    Ok(Some((mut update, runtime_fingerprint))) => {
                        update.drop_monitor_enabled =
                            drop_events.enabled_for_node(&request.node_id);
                        sent_version = update.version;
                        sent_runtime_fingerprint = Some(runtime_fingerprint.clone());
                        sent_drop_monitor_enabled = update.drop_monitor_enabled;
                        match tx.try_send(Ok(update)) {
                            Ok(()) => {
                                info!(
                                    node_id = %request.node_id,
                                    interface = %request.interface_name,
                                    version = sent_version,
                                    runtime_fingerprint,
                                    "xDS pushed updated policy"
                                );
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!(
                                    node_id = %request.node_id,
                                    interface = %request.interface_name,
                                    "xDS policy stream client is not draining updates; closing stream"
                                );
                                break;
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        let _ = tx.try_send(Err(internal_status(err)));
                        break;
                    }
                }
                tokio::select! {
                    _ = tx.closed() => break,
                    changed = drop_monitor_changes.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let enabled = drop_events.enabled_for_node(&request.node_id);
                        if enabled != sent_drop_monitor_enabled {
                            sent_drop_monitor_enabled = enabled;
                            match tx.try_send(Ok(PolicyUpdate {
                                version: sent_version.max(0),
                                policy_json: String::new(),
                                drop_monitor_enabled: enabled,
                            })) {
                                Ok(()) => {
                                    info!(
                                        node_id = %request.node_id,
                                        interface = %request.interface_name,
                                        drop_monitor_enabled = enabled,
                                        "xDS pushed drop monitor setting"
                                    );
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => break,
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    warn!(
                                        node_id = %request.node_id,
                                        interface = %request.interface_name,
                                        "xDS policy stream client is not draining monitor updates; closing stream"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    _ = tokio::time::sleep(interval) => {}
                }
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

    async fn report_drop_events(
        &self,
        request: Request<Streaming<DropEvent>>,
    ) -> std::result::Result<Response<DropEventResponse>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(unauthenticated_status());
        }
        let mut stream = request.into_inner();
        let mut accepted = 0_u64;
        while let Some(event) = stream.message().await? {
            self.drop_events.publish(DropEventView {
                node_id: event.node_id,
                interface_name: event.interface_name,
                time: event.time,
                event_time_ns: event.event_time_ns,
                cpu: event.cpu,
                reason: event.reason,
                src: event.src,
                family: event.family,
                proto: event.proto,
                dport: event.dport,
                country: (!event.country.trim().is_empty()).then_some(event.country),
                action: event.action,
            });
            accepted += 1;
        }
        Ok(Response::new(DropEventResponse { accepted }))
    }
}

impl XdsService {
    fn authorized(&self, metadata: &MetadataMap) -> bool {
        let Some(expected) = self.agent_token.as_deref() else {
            return true;
        };
        if metadata_token(metadata).is_some_and(|token| constant_time_eq(token, expected)) {
            return true;
        }
        warn!("missing or invalid xDS agent token");
        false
    }
}

fn reject_unsafe_unauthenticated_bind(bind: SocketAddr, agent_token: Option<&str>) -> Result<()> {
    if agent_token.is_some()
        || bind.ip().is_loopback()
        || env_flag("XDP_FIREWALL_ALLOW_UNAUTHENTICATED_XDS")
    {
        if agent_token.is_none() {
            warn!(
                %bind,
                "xDS is running without agent token authentication"
            );
        }
        return Ok(());
    }
    bail!(
        "xDS agent token is required when binding xDS to non-loopback address {bind}; set XDP_FIREWALL_AGENT_TOKEN or bind xDS to 127.0.0.1"
    )
}

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..len {
        let l = left.get(index).copied().unwrap_or(0);
        let r = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(l ^ r);
    }
    diff == 0
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

async fn build_policy_update(
    db: &DatabaseConnection,
    current_version: i64,
    current_runtime_fingerprint: Option<&str>,
    runtime_trusted_cidrs: &RuntimeTrustedCidrs,
) -> Result<Option<(PolicyUpdate, String)>> {
    let version = latest_version(db).await?;
    let runtime_cidrs = runtime_trusted_cidrs.current().await;
    let runtime_fingerprint = cidr_fingerprint(&runtime_cidrs);
    if version <= current_version
        && (!runtime_trusted_cidrs.enabled()
            || current_runtime_fingerprint == Some(runtime_fingerprint.as_str()))
    {
        return Ok(None);
    }
    let mut snapshot = firewall::load_policy(db, firewall::DEFAULT_POLICY_NAME).await?;
    inject_runtime_trusted_cidrs(&mut snapshot, runtime_cidrs);
    let policy_json = serde_json::to_string(&snapshot)?;
    Ok(Some((
        PolicyUpdate {
            version,
            policy_json,
            drop_monitor_enabled: false,
        },
        runtime_fingerprint,
    )))
}

async fn load_xds_snapshot(
    db: &DatabaseConnection,
    runtime_trusted_cidrs: &RuntimeTrustedCidrs,
) -> Result<(firewall::PolicySnapshot, String)> {
    let runtime_cidrs = runtime_trusted_cidrs.current().await;
    let runtime_fingerprint = cidr_fingerprint(&runtime_cidrs);
    let mut snapshot = firewall::load_policy(db, firewall::DEFAULT_POLICY_NAME).await?;
    inject_runtime_trusted_cidrs(&mut snapshot, runtime_cidrs);
    Ok((snapshot, runtime_fingerprint))
}

fn inject_runtime_trusted_cidrs(snapshot: &mut firewall::PolicySnapshot, cidrs: Vec<IpNet>) {
    let mut seen = snapshot
        .trusted_cidrs
        .iter()
        .map(|trusted| trusted.cidr)
        .collect::<HashSet<_>>();
    let mut added = 0_usize;
    for cidr in cidrs {
        if seen.insert(cidr) {
            snapshot.trusted_cidrs.push(firewall::TrustedCidrPolicy {
                cidr,
                comment: Some("runtime xDS trusted CIDR".to_string()),
            });
            added += 1;
        }
    }
    if added > 0 {
        info!(
            added,
            total_trusted_cidrs = snapshot.trusted_cidrs.len(),
            "injected runtime trusted CIDRs into xDS policy snapshot"
        );
    }
}

fn cidr_fingerprint(cidrs: &[IpNet]) -> String {
    let mut values = cidrs.iter().map(ToString::to_string).collect::<Vec<_>>();
    values.sort();
    values.join(",")
}

fn normalize_runtime_trusted_cidrs(values: &[String]) -> Result<Vec<IpNet>> {
    let mut cidrs = Vec::new();
    let mut seen = HashSet::new();
    for value in values
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let cidr = value
            .parse::<IpNet>()
            .with_context(|| format!("invalid runtime trusted CIDR '{value}'"))?;
        if seen.insert(cidr) {
            cidrs.push(cidr);
        }
    }
    Ok(cidrs)
}

async fn upsert_heartbeat(db: &DatabaseConnection, request: HeartbeatRequest) -> Result<()> {
    let now = chrono::Utc::now().naive_utc();
    let public_error = if request.error.trim().is_empty() {
        None
    } else {
        Some(security::public_error_message(&request.error))
    };
    node::Entity::insert(node::ActiveModel {
        node_id: Set(request.node_id),
        policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
        interface_name: Set(request.interface_name),
        last_seen_at: Set(now),
        last_applied_version: Set(request.last_applied_version),
        status: Set(request.status),
        error: Set(public_error),
    })
    .on_conflict(
        OnConflict::column(node::Column::NodeId)
            .update_columns([
                node::Column::PolicyName,
                node::Column::InterfaceName,
                node::Column::LastSeenAt,
                node::Column::LastAppliedVersion,
                node::Column::Status,
                node::Column::Error,
            ])
            .to_owned(),
    )
    .exec_without_returning(db)
    .await?;
    Ok(())
}

fn internal_status(error: impl std::fmt::Display) -> Status {
    Status::internal(error.to_string())
}

fn unauthenticated_status() -> Status {
    Status::unauthenticated("missing or invalid xDS agent token")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_tokens() {
        assert!(constant_time_eq("agent-token", "agent-token"));
        assert!(!constant_time_eq("agent-token", "agent-tokem"));
        assert!(!constant_time_eq("agent-token", "agent-token-extra"));
    }

    #[test]
    fn drop_event_hub_tracks_all_and_node_scoped_subscriptions() {
        let hub = DropEventHub::new();
        assert!(!hub.enabled_for_node("node-a"));

        let node_subscription = hub.subscribe(Some("node-a".to_string()));
        assert!(hub.enabled_for_node("node-a"));
        assert!(!hub.enabled_for_node("node-b"));

        let all_subscription = hub.subscribe(None);
        assert!(hub.enabled_for_node("node-b"));

        drop(node_subscription);
        assert!(hub.enabled_for_node("node-a"));
        assert!(hub.enabled_for_node("node-b"));

        drop(all_subscription);
        assert!(!hub.enabled_for_node("node-a"));
        assert!(!hub.enabled_for_node("node-b"));
    }
}
