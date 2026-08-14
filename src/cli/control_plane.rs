use clap::Args;

#[derive(Debug, Args, Clone)]
pub struct DatabaseArgs {
    #[arg(
        long,
        env = "DATABASE_URL",
        help = "SQLite, PostgreSQL, or MySQL URL required by control-plane database commands, for example sqlite://xdp-firewall.db?mode=rwc, postgres://..., or mysql://..."
    )]
    pub database_url: String,
}

#[derive(Debug, Args, Clone)]
pub struct ApiArgs {
    #[command(flatten)]
    pub database: DatabaseArgs,
    #[command(flatten)]
    pub k8s: K8sDiscoveryArgs,
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub bind: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDS_BIND",
        default_value = "0.0.0.0:50051",
        help = "gRPC xDS bind address exposed by the API control-plane process."
    )]
    pub xds_bind: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDS_PUSH_INTERVAL_SECONDS",
        default_value_t = 5,
        help = "Minimum xDS policy push interval in seconds. The control plane checks for changed policy versions at this cadence."
    )]
    pub xds_push_interval_seconds: u64,
    #[arg(
        long,
        env = "XDP_FIREWALL_AGENT_TOKEN",
        help = "Bearer token required from XDP agents. Required when xDS binds to a non-loopback address."
    )]
    pub agent_token: Option<String>,
    #[arg(
        long = "trusted-cidr",
        alias = "trusted-cidrs",
        env = "XDP_FIREWALL_TRUSTED_CIDRS",
        value_delimiter = ',',
        help = "Runtime-only highest-priority source CIDR whitelist injected into xDS snapshots. Can be repeated or comma-separated. These prefixes are not persisted to the policy database."
    )]
    pub trusted_cidrs: Vec<String>,
}

#[derive(Debug, Args, Clone)]
pub struct XdsArgs {
    #[command(flatten)]
    pub database: DatabaseArgs,
    #[command(flatten)]
    pub k8s: K8sDiscoveryArgs,
    #[arg(long, default_value = "0.0.0.0:50051")]
    pub bind: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_XDS_PUSH_INTERVAL_SECONDS",
        default_value_t = 5,
        help = "Minimum xDS policy push interval in seconds. The control plane checks for changed policy versions at this cadence."
    )]
    pub push_interval_seconds: u64,
    #[arg(
        long,
        env = "XDP_FIREWALL_AGENT_TOKEN",
        help = "Bearer token required from XDP agents. Required when xDS binds to a non-loopback address."
    )]
    pub agent_token: Option<String>,
    #[arg(
        long = "trusted-cidr",
        alias = "trusted-cidrs",
        env = "XDP_FIREWALL_TRUSTED_CIDRS",
        value_delimiter = ',',
        help = "Runtime-only highest-priority source CIDR whitelist injected into xDS snapshots. Can be repeated or comma-separated. These prefixes are not persisted to the policy database."
    )]
    pub trusted_cidrs: Vec<String>,
}

#[derive(Debug, Args, Clone)]
pub struct K8sDiscoveryArgs {
    #[arg(
        long,
        env = "XDP_FIREWALL_K8S_DISCOVERY",
        default_value_t = false,
        help = "Enable Kubernetes runtime address discovery in the control plane. Discovered node IPs, Pod CIDRs, and Service CIDRs are injected into xDS snapshots as runtime-only whitelist entries and are not persisted."
    )]
    pub k8s_discovery: bool,
    #[arg(
        long,
        env = "XDP_FIREWALL_K8S_API_SERVER",
        help = "Kubernetes API server URL. Defaults to https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS or KUBERNETES_SERVICE_PORT}."
    )]
    pub k8s_api_server: Option<String>,
    #[arg(
        long,
        env = "XDP_FIREWALL_K8S_TOKEN_PATH",
        default_value = "/var/run/secrets/kubernetes.io/serviceaccount/token",
        help = "Kubernetes service account bearer token path used by control-plane discovery."
    )]
    pub k8s_token_path: String,
    #[arg(
        long,
        env = "XDP_FIREWALL_K8S_CA_CERT_PATH",
        default_value = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        help = "Kubernetes service account CA certificate path used by control-plane discovery."
    )]
    pub k8s_ca_cert_path: String,
}
