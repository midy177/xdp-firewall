use clap::{Parser, Subcommand};

mod agent;
mod control_plane;
mod policy;
mod xdp;
mod xdp_maps;

pub use agent::{AgentArgs, AgentOfflineMode, MonitorArgs, SyncOnceArgs, XdsTlsClientArgs};
pub use control_plane::{ApiArgs, DatabaseArgs, K8sDiscoveryArgs, XdsArgs, XdsTlsServerArgs};
pub use policy::{PolicyCommand, SeedExampleArgs, ShowPolicyArgs};
pub use xdp::{XdpCommand, XdpReplaceArgs, XdpStatusArgs, XdpTempBansArgs, XdpUnloadArgs};
pub use xdp_maps::XdpMapCapacityArgs;

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Migrate(DatabaseArgs),
    Api(ApiArgs),
    Xds(XdsArgs),
    Agent(AgentArgs),
    SyncOnce(SyncOnceArgs),
    Monitor(MonitorArgs),
    Xdp {
        #[command(subcommand)]
        command: XdpCommand,
    },
    Policy {
        #[command(flatten)]
        database: DatabaseArgs,
        #[command(subcommand)]
        command: PolicyCommand,
    },
}
