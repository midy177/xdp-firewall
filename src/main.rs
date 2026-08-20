mod server_commands;

use anyhow::{Result, bail};
use clap::Parser;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};
use xdp_firewall::cli::{Cli, Command, DatabaseArgs, PolicyCommand, XdpCommand};
use xdp_firewall::{
    agent::{monitor, sync},
    data_plane::xdp,
    db,
    policy::{model::DEFAULT_POLICY_NAME, seed},
};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    install_rustls_crypto_provider();

    let cli = Cli::parse();
    info!("starting xdp-firewall");
    reject_control_plane_commands_in_agent_only_mode(&cli.command)?;
    reject_writes_in_standby_mode(&cli.command)?;
    run_command(cli.command).await
}

fn install_rustls_crypto_provider() {
    // The dependency graph enables both the ring and aws-lc-rs rustls providers
    // (tonic tls-ring plus sqlx/reqwest rustls links), so rustls cannot pick a
    // process-level provider automatically. Pin ring explicitly; aws-lc would
    // add a cmake/nasm build dependency to the agent image.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}

fn init_tracing() {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("xdp_firewall=info")),
        )
        .with_target(false)
        .init();
}

async fn run_command(command: Command) -> Result<()> {
    match command {
        Command::Migrate(args) => run_migrate_command(args).await,
        Command::Api(args) => server_commands::run_api_command(args).await,
        Command::Xds(args) => server_commands::run_xds_command(args).await,
        Command::Agent(args) => {
            info!("starting agent command");
            sync::run_agent(args).await
        }
        Command::SyncOnce(args) => {
            info!("starting sync-once command");
            sync::sync_once(args).await
        }
        Command::Monitor(args) => {
            info!("starting monitor command");
            monitor::run(args).await
        }
        Command::Xdp { command } => run_xdp_command(command),
        Command::Policy { database, command } => run_policy_command(database, command).await,
    }
}

async fn run_migrate_command(args: DatabaseArgs) -> Result<()> {
    info!("running database migrations");
    let db = db::connect(&args.database_url).await?;
    db::migrate(&db).await
}

fn run_xdp_command(command: XdpCommand) -> Result<()> {
    match command {
        XdpCommand::Status(args) => {
            info!("starting xdp status command");
            xdp::dispatcher_status(args)
        }
        XdpCommand::TempBans(args) => {
            info!("starting xdp temp-bans command");
            xdp::dispatcher_temp_bans(args)
        }
        XdpCommand::Unload(args) => {
            info!("starting xdp unload command");
            xdp::dispatcher_unload(args)
        }
        XdpCommand::Replace(args) => {
            info!("starting xdp replace command");
            xdp::dispatcher_replace(args)
        }
    }
}

async fn run_policy_command(database: DatabaseArgs, command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::SeedExample(args) => {
            let db = db::connect(&database.database_url).await?;
            db::migrate(&db).await?;
            seed::seed_example_policy(&db, args).await
        }
        PolicyCommand::Show(args) => {
            let db = db::connect(&database.database_url).await?;
            db::migrate(&db).await?;
            seed::ensure_builtin_policy(&db, DEFAULT_POLICY_NAME).await?;
            seed::show_policy(&db, args).await
        }
    }
}

fn reject_control_plane_commands_in_agent_only_mode(command: &Command) -> Result<()> {
    let agent_only = std::env::var("XDP_FIREWALL_AGENT_ONLY")
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    if !agent_only
        || matches!(
            command,
            Command::Agent(_) | Command::SyncOnce(_) | Command::Monitor(_) | Command::Xdp { .. }
        )
    {
        return Ok(());
    }
    bail!(
        "control-plane database commands are disabled in this agent-only container; use the API/control-plane container or HTTP API to inspect policy"
    )
}

fn reject_writes_in_standby_mode(command: &Command) -> Result<()> {
    let standby = std::env::var("XDP_FIREWALL_STANDBY")
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    if !standby {
        return Ok(());
    }
    let is_write_command = matches!(
        command,
        Command::Migrate(_)
            | Command::Policy {
                command: PolicyCommand::SeedExample(_),
                ..
            }
    );
    if !is_write_command {
        return Ok(());
    }
    bail!(
        "control-plane writes are disabled in standby read-only mode; use a non-standby control plane to migrate or seed policy"
    )
}
