use crate::cli::XdsArgs;
use crate::db::entities::{geo_country_policy, geo_ip_prefix, node, policy_version, temp_ban};
use crate::{firewall, geo, k8s, monitor, security};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait, sea_query::OnConflict,
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
use tracing::{debug, info, trace, warn};

const TEMP_BAN_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const GEO_IP_REFRESH_INTERVAL: Duration = Duration::from_secs(86_400);
const GEO_IP_REFRESH_RETRY_INTERVAL: Duration = Duration::from_secs(300);
const K8S_WATCH_TIMEOUT: Duration = Duration::from_secs(300);
const K8S_WATCH_RECONNECT_DELAY: Duration = Duration::from_secs(5);
const K8S_WATCH_CHANGE_DEBOUNCE: Duration = Duration::from_secs(1);

pub mod proto {
    tonic::include_proto!("xdp_firewall.xds.v1");
}

use proto::firewall_xds_client::FirewallXdsClient;
use proto::firewall_xds_server::{FirewallXds, FirewallXdsServer};
use proto::{
    DropEvent, DropEventResponse, FetchGeoPrefixesRequest, FetchGeoPrefixesResponse,
    FetchPolicyRequest, FetchPolicyResponse, GeoPrefix as ProtoGeoPrefix, HeartbeatRequest,
    HeartbeatResponse, PolicyUpdate, StreamPolicyRequest,
};

const GEO_PREFIX_PAGE_SIZE: u32 = 4096;
const MAX_GEO_PREFIX_PAGE_SIZE: u32 = 10_000;

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
    temp_ban_cleanup: TempBanCleanup,
    geo_lookup: geo::GeoIpLookup,
}

#[derive(Clone)]
struct TempBanCleanup {
    state: Arc<Mutex<TempBanCleanupState>>,
    interval: Duration,
}

#[derive(Default)]
struct TempBanCleanupState {
    last_success: Option<Instant>,
    running: bool,
}

#[derive(Clone)]
struct GeoIpRefresh {
    state: Arc<StdMutex<GeoIpRefreshState>>,
    interval: Duration,
    geo_lookup: geo::GeoIpLookup,
}

#[derive(Default)]
struct GeoIpRefreshState {
    last_success: Option<Instant>,
    last_attempt: Option<Instant>,
    running: bool,
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

impl TempBanCleanup {
    fn new(interval: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(TempBanCleanupState::default())),
            interval,
        }
    }

    async fn maybe_run(&self, db: &DatabaseConnection) -> Result<()> {
        let started_at = Instant::now();
        {
            let mut state = self.state.lock().await;
            if state.running {
                return Ok(());
            }
            if state
                .last_success
                .and_then(|last| started_at.checked_duration_since(last))
                .is_some_and(|elapsed| elapsed < self.interval)
            {
                return Ok(());
            }
            state.running = true;
        }

        let result = cleanup_expired_temp_bans(db).await;
        {
            let mut state = self.state.lock().await;
            state.running = false;
            if result.is_ok() {
                state.last_success = Some(started_at);
            }
        }

        let (deleted, version) = result?;
        if let Some(version) = version {
            info!(
                deleted_expired_temp_bans = deleted,
                version, "cleaned up expired temporary bans during xDS push tick"
            );
        }
        Ok(())
    }
}

impl GeoIpRefresh {
    fn new(interval: Duration, geo_lookup: geo::GeoIpLookup) -> Self {
        Self {
            state: Arc::new(StdMutex::new(GeoIpRefreshState {
                last_success: Some(Instant::now()),
                ..Default::default()
            })),
            interval,
            geo_lookup,
        }
    }

    async fn maybe_run(&self, db: &DatabaseConnection) -> Result<()> {
        let started_at = Instant::now();
        let (running, retry_throttled, within_interval) = {
            let state = self.state.lock().expect("geo IP refresh mutex poisoned");
            (
                state.running,
                state
                    .last_attempt
                    .and_then(|last| started_at.checked_duration_since(last))
                    .is_some_and(|elapsed| elapsed < GEO_IP_REFRESH_RETRY_INTERVAL),
                state
                    .last_success
                    .and_then(|last| started_at.checked_duration_since(last))
                    .is_some_and(|elapsed| elapsed < self.interval),
            )
        };
        if running || retry_throttled {
            return Ok(());
        }
        let missing_lists = if !within_interval {
            false
        } else {
            geo_ip_lists_missing(db).await?
        };
        if within_interval && !missing_lists {
            return Ok(());
        }

        {
            let mut state = self.state.lock().expect("geo IP refresh mutex poisoned");
            if state.running {
                return Ok(());
            }
            if state
                .last_attempt
                .and_then(|last| started_at.checked_duration_since(last))
                .is_some_and(|elapsed| elapsed < GEO_IP_REFRESH_RETRY_INTERVAL)
            {
                return Ok(());
            }
            let within_interval = state
                .last_success
                .and_then(|last| started_at.checked_duration_since(last))
                .is_some_and(|elapsed| elapsed < self.interval);
            if within_interval && !missing_lists {
                return Ok(());
            }
            state.running = true;
            state.last_attempt = Some(started_at);
        }
        let state = self.state.clone();
        let db = db.clone();
        let geo_lookup = self.geo_lookup.clone();
        tokio::spawn(async move {
            let result: Result<geo::GeoRefreshReport> = async {
                let report = refresh_geo_ip_lists(&db).await?;
                if report.changed_country_count > 0 {
                    let lookup_prefixes = geo_lookup.rebuild_from_db(&db).await?;
                    let version = latest_version(&db).await?;
                    info!(
                        checked_countries = report.checked_country_count,
                        changed_countries = report.changed_country_count,
                        prefixes = report.prefix_count,
                        lookup_prefixes,
                        version,
                        "refreshed changed country IP lists during xDS push tick"
                    );
                }
                Ok(report)
            }
            .await;
            let mut guard = state.lock().expect("geo IP refresh mutex poisoned");
            guard.running = false;
            match result {
                Ok(report) if report.failed_country_count == 0 && !report.running => {
                    guard.last_success = Some(started_at);
                }
                Ok(report) if report.running => {
                    debug!(
                        status = %report.refresh_status,
                        "country IP refresh is already running elsewhere; skipping automatic xDS refresh"
                    );
                }
                Ok(report) => {
                    warn!(
                        status = %report.refresh_status,
                        failed_countries = report.failed_country_count,
                        "country IP refresh did not complete cleanly during xDS push tick"
                    );
                }
                Err(err) => {
                    warn!(error = %err, "country IP refresh failed during xDS push tick");
                }
            }
        });
        Ok(())
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
    cache: Arc<Mutex<K8sDiscoveryCache>>,
}

#[derive(Default)]
struct K8sDiscoveryCache {
    cidrs: Vec<IpNet>,
    initialized: bool,
    service_cidr_partial: bool,
    last_refresh_failed: bool,
}

impl RuntimeTrustedCidrs {
    fn new(configured: Vec<IpNet>, k8s_discovery: Option<k8s::KubernetesDiscovery>) -> Self {
        Self {
            configured,
            k8s_discovery,
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

        if self.k8s_discovery.is_none() {
            return cidrs;
        }
        let cached = self.cache.lock().await.cidrs.clone();
        for cidr in cached {
            if seen.insert(cidr) {
                cidrs.push(cidr);
            }
        }
        cidrs
    }

    async fn initial_refresh(&self) {
        let Some(discovery) = self.k8s_discovery.as_ref() else {
            return;
        };
        if let Err(err) = refresh_k8s_discovery_cache(&self.cache, discovery, "initial").await {
            warn!(
                error = %err,
                "initial Kubernetes runtime address discovery failed; continuing with static runtime trusted CIDRs"
            );
        }
    }

    fn spawn_watch(&self) {
        let Some(discovery) = self.k8s_discovery.clone() else {
            return;
        };
        let cache = self.cache.clone();
        tokio::spawn(async move {
            run_k8s_discovery_watch(cache, discovery).await;
        });
    }
}

async fn run_k8s_discovery_watch(
    cache: Arc<Mutex<K8sDiscoveryCache>>,
    discovery: k8s::KubernetesDiscovery,
) {
    loop {
        let watch_services = {
            let cache = cache.lock().await;
            cache.service_cidr_partial
        };
        let outcome = wait_for_k8s_watch_change(discovery.clone(), watch_services).await;
        match outcome {
            Ok(true) => {
                if let Err(err) =
                    refresh_k8s_discovery_cache(&cache, &discovery, "watch-change").await
                {
                    mark_k8s_discovery_failed(&cache).await;
                    warn!(
                        error = %err,
                        "Kubernetes runtime address discovery failed after watch event; keeping last cached runtime trusted CIDRs"
                    );
                }
                tokio::time::sleep(K8S_WATCH_CHANGE_DEBOUNCE).await;
            }
            Ok(false) => {}
            Err(err) => {
                mark_k8s_discovery_failed(&cache).await;
                warn!(
                    error = %err,
                    retry_seconds = K8S_WATCH_RECONNECT_DELAY.as_secs(),
                    "Kubernetes watch failed; keeping last cached runtime trusted CIDRs before reconnect"
                );
                tokio::time::sleep(K8S_WATCH_RECONNECT_DELAY).await;
            }
        }
    }
}

async fn wait_for_k8s_watch_change(
    discovery: k8s::KubernetesDiscovery,
    watch_services: bool,
) -> Result<bool> {
    let (tx, mut rx) = mpsc::channel(4);
    let mut handles = Vec::new();
    for (label, path) in k8s_watch_targets(watch_services) {
        let tx = tx.clone();
        let discovery = discovery.clone();
        handles.push(tokio::spawn(async move {
            let result = discovery
                .watch_until_change(path, label, K8S_WATCH_TIMEOUT)
                .await;
            let _ = tx.send((label, result)).await;
        }));
    }
    drop(tx);
    let mut unsupported = 0_usize;
    while let Some((label, result)) = rx.recv().await {
        match result {
            Ok(k8s::KubernetesWatchOutcome::Changed) => {
                debug!(
                    label,
                    "Kubernetes watch observed a runtime CIDR source change"
                );
                for handle in handles {
                    handle.abort();
                }
                return Ok(true);
            }
            Ok(k8s::KubernetesWatchOutcome::Ended) => {
                trace!(label, "Kubernetes watch stream ended; reconnecting");
                for handle in handles {
                    handle.abort();
                }
                return Ok(false);
            }
            Ok(k8s::KubernetesWatchOutcome::Unsupported) => {
                unsupported += 1;
                debug!(label, "Kubernetes watch target is unsupported");
                if unsupported == handles.len() {
                    bail!("all Kubernetes watch targets are unsupported");
                }
            }
            Err(err) => {
                for handle in handles {
                    handle.abort();
                }
                return Err(err).with_context(|| format!("Kubernetes watch '{label}' failed"));
            }
        }
    }
    bail!("all Kubernetes watch streams ended without a change notification")
}

fn k8s_watch_targets(watch_services: bool) -> &'static [(&'static str, &'static str)] {
    if watch_services {
        &[("nodes", "/api/v1/nodes"), ("services", "/api/v1/services")]
    } else {
        &[
            ("nodes", "/api/v1/nodes"),
            ("servicecidrs", "/apis/networking.k8s.io/v1/servicecidrs"),
        ]
    }
}

async fn refresh_k8s_discovery_cache(
    cache: &Arc<Mutex<K8sDiscoveryCache>>,
    discovery: &k8s::KubernetesDiscovery,
    reason: &'static str,
) -> Result<()> {
    let discovered = discovery.discover().await?;
    let mut cache = cache.lock().await;
    let first = !cache.initialized;
    let changed = cache.cidrs != discovered.cidrs;
    let recovered = cache.last_refresh_failed;
    if discovered.service_cidr_partial {
        warn!(
            service_entries = discovered.service_cidrs,
            "Kubernetes ServiceCIDR API is unavailable; using existing Service ClusterIPs as partial runtime whitelist"
        );
    }
    if first || changed || recovered {
        info!(
            reason,
            node_ips = discovered.node_ips,
            pod_cidrs = discovered.pod_cidrs,
            service_cidrs = discovered.service_cidrs,
            service_cidr_partial = discovered.service_cidr_partial,
            total = discovered.cidrs.len(),
            changed,
            recovered,
            "refreshed Kubernetes runtime trusted CIDRs"
        );
    } else {
        trace!(
            reason,
            node_ips = discovered.node_ips,
            pod_cidrs = discovered.pod_cidrs,
            service_cidrs = discovered.service_cidrs,
            service_cidr_partial = discovered.service_cidr_partial,
            total = discovered.cidrs.len(),
            "Kubernetes runtime trusted CIDRs unchanged"
        );
    }
    cache.cidrs = discovered.cidrs;
    cache.initialized = true;
    cache.service_cidr_partial = discovered.service_cidr_partial;
    cache.last_refresh_failed = false;
    Ok(())
}

async fn mark_k8s_discovery_failed(cache: &Arc<Mutex<K8sDiscoveryCache>>) {
    cache.lock().await.last_refresh_failed = true;
}

pub async fn serve(
    db: DatabaseConnection,
    args: XdsArgs,
    drop_events: DropEventHub,
    geo_lookup: geo::GeoIpLookup,
) -> Result<()> {
    let bind: SocketAddr = args
        .bind
        .parse()
        .with_context(|| format!("invalid xDS bind address '{}'", args.bind))?;
    let agent_token = args.agent_token.filter(|token| !token.trim().is_empty());
    reject_unsafe_unauthenticated_bind(bind, agent_token.as_deref())?;
    let push_interval = Duration::from_secs(args.push_interval_seconds.max(1));
    let runtime_trusted_cidrs = normalize_runtime_trusted_cidrs(&args.trusted_cidrs)?;
    let k8s_discovery = k8s::KubernetesDiscovery::from_args(&args.k8s)?;
    let runtime_trusted_cidrs = RuntimeTrustedCidrs::new(runtime_trusted_cidrs, k8s_discovery);
    runtime_trusted_cidrs.initial_refresh().await;
    runtime_trusted_cidrs.spawn_watch();
    info!(
        %bind,
        auth_enabled = agent_token.is_some(),
        push_interval_seconds = push_interval.as_secs(),
        runtime_trusted_cidrs = runtime_trusted_cidrs.configured.len(),
        k8s_discovery_enabled = runtime_trusted_cidrs.k8s_discovery.is_some(),
        k8s_watch_timeout_seconds = K8S_WATCH_TIMEOUT.as_secs(),
        "xDS gRPC server listening"
    );
    let geo_ip_refresh = GeoIpRefresh::new(GEO_IP_REFRESH_INTERVAL, geo_lookup.clone());
    spawn_geo_refresh_loop(db.clone(), geo_ip_refresh.clone(), GEO_IP_REFRESH_INTERVAL);
    Server::builder()
        .add_service(FirewallXdsServer::new(XdsService {
            db,
            agent_token,
            push_interval,
            drop_events,
            runtime_trusted_cidrs,
            temp_ban_cleanup: TempBanCleanup::new(TEMP_BAN_CLEANUP_INTERVAL),
            geo_lookup,
        }))
        .serve(bind)
        .await
        .context("xDS gRPC server failed")
}

fn spawn_geo_refresh_loop(
    db: DatabaseConnection,
    geo_ip_refresh: GeoIpRefresh,
    interval: Duration,
) {
    tokio::spawn(async move {
        loop {
            if let Err(err) = geo_ip_refresh.maybe_run(&db).await {
                warn!(error = %err, "country IP background refresh trigger failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
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
            supports_external_geo_prefixes: true,
        })?;
        let response = self.inner.fetch_policy(request).await?.into_inner();
        if response.unchanged {
            return Ok(None);
        }
        let mut snapshot: firewall::PolicySnapshot = serde_json::from_str(&response.policy_json)
            .context("xDS control plane returned invalid policy JSON")?;
        if response.external_geo_prefixes {
            snapshot.geo_prefixes = self.fetch_geo_prefixes(response.geo_prefix_version).await?;
        }
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
            supports_external_geo_prefixes: true,
        })?;
        Ok(self.inner.stream_policy(request).await?.into_inner())
    }

    pub async fn policy_from_update(
        &mut self,
        update: PolicyUpdate,
    ) -> Result<(i64, Option<firewall::PolicySnapshot>, bool)> {
        let mut snapshot = if update.policy_json.trim().is_empty() {
            None
        } else {
            Some(
                serde_json::from_str::<firewall::PolicySnapshot>(&update.policy_json)
                    .context("xDS control plane returned invalid policy JSON")?,
            )
        };
        if let Some(snapshot) = snapshot.as_mut()
            && update.external_geo_prefixes
        {
            snapshot.geo_prefixes = self.fetch_geo_prefixes(update.geo_prefix_version).await?;
        }
        Ok((update.version, snapshot, update.drop_monitor_enabled))
    }

    async fn fetch_geo_prefixes(
        &mut self,
        version: i64,
    ) -> Result<Vec<firewall::GeoIpPrefixPolicy>> {
        let mut prefixes = Vec::new();
        let mut page_token = String::new();
        loop {
            let request = self.with_auth(FetchGeoPrefixesRequest {
                version,
                page_size: GEO_PREFIX_PAGE_SIZE,
                page_token,
            })?;
            let response = self.inner.fetch_geo_prefixes(request).await?.into_inner();
            for prefix in response.prefixes {
                prefixes.push(firewall::GeoIpPrefixPolicy {
                    cidr: prefix
                        .cidr
                        .parse()
                        .with_context(|| format!("invalid xDS GeoIP CIDR '{}'", prefix.cidr))?,
                    country: geo::normalize_country(&prefix.country)?,
                });
            }
            if response.next_page_token.trim().is_empty() {
                break;
            }
            page_token = response.next_page_token;
        }
        Ok(prefixes)
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
                external_geo_prefixes: false,
                geo_prefix_version: 0,
            }));
        }

        let external_geo_prefixes = request.supports_external_geo_prefixes;
        let (snapshot, runtime_fingerprint) = load_xds_snapshot(
            &self.db,
            &self.runtime_trusted_cidrs,
            !external_geo_prefixes,
        )
        .await
        .map_err(internal_status)?;
        let geo_prefix_version = if external_geo_prefixes { version } else { 0 };
        let policy_json = serde_json::to_string(&snapshot).map_err(internal_status)?;
        info!(
            node_id = %request.node_id,
            interface = %request.interface_name,
            requested_version = request.current_version,
            version,
            external_geo_prefixes,
            runtime_fingerprint,
            "xDS returned updated policy"
        );
        Ok(Response::new(FetchPolicyResponse {
            version,
            unchanged: false,
            policy_json,
            external_geo_prefixes,
            geo_prefix_version,
        }))
    }

    async fn fetch_geo_prefixes(
        &self,
        request: Request<FetchGeoPrefixesRequest>,
    ) -> std::result::Result<Response<FetchGeoPrefixesResponse>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(unauthenticated_status());
        }
        let request = request.into_inner();
        let version = latest_version(&self.db).await.map_err(internal_status)?;
        if request.version > 0 && request.version != version {
            return Err(Status::failed_precondition(
                "GeoIP prefix version changed; refetch policy",
            ));
        }
        let page_size = if request.page_size == 0 {
            GEO_PREFIX_PAGE_SIZE
        } else {
            request.page_size.min(MAX_GEO_PREFIX_PAGE_SIZE)
        } as usize;
        let countries = enabled_geo_countries(&self.db)
            .await
            .map_err(internal_status)?;
        let page = geo::load_persisted_geo_prefix_page(
            &self.db,
            &countries,
            Some(&request.page_token),
            page_size,
        )
        .await
        .map_err(internal_status)?;
        let prefixes = page
            .prefixes
            .iter()
            .map(|prefix| {
                Ok(ProtoGeoPrefix {
                    cidr: geo::geo_prefix_to_cidr(prefix),
                    country: geo::decode_country(prefix.country)
                        .with_context(|| "invalid persisted geo country code")?,
                })
            })
            .collect::<Result<Vec<_>>>()
            .map_err(internal_status)?;
        Ok(Response::new(FetchGeoPrefixesResponse {
            version,
            prefixes,
            next_page_token: page.next_page_token.unwrap_or_default(),
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
        let temp_ban_cleanup = self.temp_ban_cleanup.clone();
        let mut drop_monitor_changes = drop_events.subscribe_changes();
        let (tx, rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let supports_external_geo_prefixes = request.supports_external_geo_prefixes;
            let mut sent_version = request.current_version;
            let mut sent_runtime_fingerprint = None;
            let mut sent_drop_monitor_enabled = drop_events.enabled_for_node(&request.node_id);
            if sent_drop_monitor_enabled
                && tx
                    .try_send(Ok(PolicyUpdate {
                        version: sent_version.max(0),
                        policy_json: String::new(),
                        drop_monitor_enabled: sent_drop_monitor_enabled,
                        external_geo_prefixes: false,
                        geo_prefix_version: 0,
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
                    &temp_ban_cleanup,
                    supports_external_geo_prefixes,
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
                                external_geo_prefixes: false,
                                geo_prefix_version: 0,
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
        let geo_lookup = self.geo_lookup.clone();
        let mut accepted = 0_u64;
        while let Some(event) = stream.message().await? {
            let country = (!event.country.trim().is_empty())
                .then(|| event.country.trim().to_ascii_uppercase())
                .or_else(|| {
                    event
                        .src
                        .parse()
                        .ok()
                        .and_then(|ip| geo_lookup.lookup_country(ip))
                });
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
                country,
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

async fn cleanup_expired_temp_bans(db: &DatabaseConnection) -> Result<(u64, Option<i64>)> {
    let now = chrono::Utc::now().naive_utc();
    let (deleted, version) = db
        .transaction::<_, (u64, Option<i64>), DbErr>(|txn| {
            Box::pin(async move {
                let deleted = temp_ban::Entity::delete_many()
                    .filter(temp_ban::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
                    .filter(temp_ban::Column::ExpiresAt.lte(now))
                    .exec(txn)
                    .await?
                    .rows_affected;
                let version = if deleted > 0 {
                    Some(
                        crate::db::next_policy_version_in_transaction(
                            txn,
                            firewall::DEFAULT_POLICY_NAME,
                        )
                        .await?,
                    )
                } else {
                    None
                };
                Ok((deleted, version))
            })
        })
        .await?;
    Ok((deleted, version))
}

async fn refresh_geo_ip_lists(db: &DatabaseConnection) -> Result<geo::GeoRefreshReport> {
    geo::refresh_all_ipdeny_lists(db).await
}

async fn geo_ip_lists_missing(db: &DatabaseConnection) -> Result<bool> {
    let rows = geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Enabled.eq(true))
        .all(db)
        .await?;
    for row in rows {
        let country = geo::normalize_country(&row.country)?;
        let has_country_list = geo_ip_prefix::Entity::find()
            .filter(geo_ip_prefix::Column::Country.eq(country))
            .one(db)
            .await?
            .is_some();
        if !has_country_list {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn enabled_geo_countries(db: &DatabaseConnection) -> Result<Vec<String>> {
    Ok(geo_country_policy::Entity::find()
        .filter(geo_country_policy::Column::PolicyName.eq(firewall::DEFAULT_POLICY_NAME))
        .filter(geo_country_policy::Column::Enabled.eq(true))
        .order_by_asc(geo_country_policy::Column::Country)
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.country)
        .collect())
}

async fn build_policy_update(
    db: &DatabaseConnection,
    current_version: i64,
    current_runtime_fingerprint: Option<&str>,
    runtime_trusted_cidrs: &RuntimeTrustedCidrs,
    temp_ban_cleanup: &TempBanCleanup,
    supports_external_geo_prefixes: bool,
) -> Result<Option<(PolicyUpdate, String)>> {
    temp_ban_cleanup.maybe_run(db).await?;
    let version = latest_version(db).await?;
    let runtime_cidrs = runtime_trusted_cidrs.current().await;
    let runtime_fingerprint = cidr_fingerprint(&runtime_cidrs);
    if version <= current_version
        && (!runtime_trusted_cidrs.enabled()
            || current_runtime_fingerprint == Some(runtime_fingerprint.as_str()))
    {
        return Ok(None);
    }
    let mut snapshot = if supports_external_geo_prefixes {
        firewall::load_policy_without_geo_prefixes(db, firewall::DEFAULT_POLICY_NAME).await?
    } else {
        firewall::load_policy(db, firewall::DEFAULT_POLICY_NAME).await?
    };
    inject_runtime_trusted_cidrs(&mut snapshot, runtime_cidrs);
    let geo_prefix_version = if supports_external_geo_prefixes {
        version
    } else {
        0
    };
    let policy_json = serde_json::to_string(&snapshot)?;
    Ok(Some((
        PolicyUpdate {
            version,
            policy_json,
            drop_monitor_enabled: false,
            external_geo_prefixes: supports_external_geo_prefixes,
            geo_prefix_version,
        },
        runtime_fingerprint,
    )))
}

async fn load_xds_snapshot(
    db: &DatabaseConnection,
    runtime_trusted_cidrs: &RuntimeTrustedCidrs,
    include_geo_prefixes: bool,
) -> Result<(firewall::PolicySnapshot, String)> {
    let runtime_cidrs = runtime_trusted_cidrs.current().await;
    let runtime_fingerprint = cidr_fingerprint(&runtime_cidrs);
    let mut snapshot = if include_geo_prefixes {
        firewall::load_policy(db, firewall::DEFAULT_POLICY_NAME).await?
    } else {
        firewall::load_policy_without_geo_prefixes(db, firewall::DEFAULT_POLICY_NAME).await?
    };
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
    use sea_orm::{ActiveModelTrait, ConnectOptions, Database};

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

    #[tokio::test]
    async fn temp_ban_cleanup_deletes_expired_rows_and_bumps_version() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();

        let now = chrono::Utc::now().naive_utc();
        temp_ban::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            ip: Set("203.0.113.10".to_string()),
            protocol: Set("any".to_string()),
            port: Set(None),
            expires_at: Set(now - chrono::Duration::seconds(1)),
            comment: Set(Some("expired".to_string())),
            created_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();
        temp_ban::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            ip: Set("203.0.113.20".to_string()),
            protocol: Set("tcp".to_string()),
            port: Set(Some(443)),
            expires_at: Set(now + chrono::Duration::seconds(300)),
            comment: Set(Some("active".to_string())),
            created_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        let cleanup = TempBanCleanup::new(TEMP_BAN_CLEANUP_INTERVAL);
        cleanup.maybe_run(&db).await.unwrap();

        let rows = temp_ban::Entity::find().all(&db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ip, "203.0.113.20");
        assert_eq!(latest_version(&db).await.unwrap(), 1);

        temp_ban::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            ip: Set("203.0.113.30".to_string()),
            protocol: Set("udp".to_string()),
            port: Set(Some(53)),
            expires_at: Set(now - chrono::Duration::seconds(1)),
            comment: Set(Some("expired inside throttle window".to_string())),
            created_at: Set(now),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap();

        cleanup.maybe_run(&db).await.unwrap();
        let rows = temp_ban::Entity::find().all(&db).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(latest_version(&db).await.unwrap(), 1);
    }

    fn test_service(db: DatabaseConnection) -> XdsService {
        XdsService {
            db,
            agent_token: None,
            push_interval: Duration::from_secs(1),
            drop_events: DropEventHub::new(),
            runtime_trusted_cidrs: RuntimeTrustedCidrs::new(Vec::new(), None),
            temp_ban_cleanup: TempBanCleanup::new(TEMP_BAN_CLEANUP_INTERVAL),
            geo_lookup: geo::GeoIpLookup::default(),
        }
    }

    async fn seed_enabled_country_with_prefixes(db: &DatabaseConnection) {
        let now = chrono::Utc::now().naive_utc();
        geo_country_policy::ActiveModel {
            policy_name: Set(firewall::DEFAULT_POLICY_NAME.to_string()),
            enabled: Set(true),
            country: Set("US".to_string()),
            action: Set("deny".to_string()),
            packets_per_second: Set(None),
            burst: Set(None),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap();
        geo_ip_prefix::ActiveModel {
            country: Set("US".to_string()),
            cidrs_json: Set(r#"["203.0.113.0/24","203.0.114.0/24"]"#.to_string()),
            updated_at: Set(now),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap();
        crate::db::next_policy_version(db, firewall::DEFAULT_POLICY_NAME)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fetch_geo_prefixes_rejects_stale_version() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options.sqlx_logging(false);
        let db = Database::connect(options).await.unwrap();
        crate::db::migrate(&db).await.unwrap();
        seed_enabled_country_with_prefixes(&db).await;
        let version = latest_version(&db).await.unwrap();

        let service = test_service(db);

        // Matching version returns the persisted prefixes.
        let ok = service
            .fetch_geo_prefixes(Request::new(FetchGeoPrefixesRequest {
                version,
                page_size: 0,
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ok.version, version);
        assert_eq!(ok.prefixes.len(), 2);
        assert!(ok.next_page_token.is_empty());

        // A stale version is rejected so the agent refetches the policy instead
        // of mixing a new policy with an old GeoIP snapshot.
        let stale = service
            .fetch_geo_prefixes(Request::new(FetchGeoPrefixesRequest {
                version: version + 1,
                page_size: 0,
                page_token: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(stale.code(), tonic::Code::FailedPrecondition);
    }
}
