use anyhow::{Context, Result, bail};
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};
use xdp_firewall::cli::{Cli, Command, PolicyCommand, XdpCommand, XdsArgs};
use xdp_firewall::{api, db, firewall, geo, monitor, sync, xdp, xds};

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("xdp_firewall=info")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    info!("starting xdp-firewall");
    reject_control_plane_commands_in_agent_only_mode(&cli.command)?;

    match cli.command {
        Command::Migrate(args) => {
            info!("running database migrations");
            let db = db::connect(&args.database_url).await?;
            db::migrate(&db).await
        }
        Command::Api(args) => {
            info!(
                trusted_cidrs = args.trusted_cidrs.len(),
                "starting api command"
            );
            let db = db::connect(&args.database.database_url).await?;
            db::migrate(&db).await?;
            firewall::ensure_builtin_policy(&db, firewall::DEFAULT_POLICY_NAME).await?;
            let xds_args = XdsArgs {
                database: args.database.clone(),
                k8s: args.k8s.clone(),
                bind: args.xds_bind.clone(),
                push_interval_seconds: args.xds_push_interval_seconds,
                agent_token: args.agent_token.clone(),
                trusted_cidrs: args.trusted_cidrs.clone(),
            };
            let drop_events = xds::DropEventHub::new();
            let geo_lookup = geo::GeoIpLookup::default();
            let loaded_geo_prefixes = geo_lookup.rebuild_from_db(&db).await?;
            info!(
                geo_prefixes = loaded_geo_prefixes,
                "loaded country IP lookup database"
            );
            let api_server = api::serve(db.clone(), args, drop_events.clone(), geo_lookup.clone());
            let xds_server = xds::serve(db, xds_args, drop_events, geo_lookup);
            tokio::select! {
                result = api_server => {
                    match result {
                        Ok(()) => {
                            error!("API HTTP server exited unexpectedly without error");
                            bail!("API HTTP server exited unexpectedly");
                        }
                        Err(err) => {
                            error!(error = %format!("{err:#}"), "API HTTP server exited with error");
                            return Err(err).context("API HTTP server exited");
                        }
                    }
                }
                result = xds_server => {
                    match result {
                        Ok(()) => {
                            error!("xDS gRPC server exited unexpectedly without error");
                            bail!("xDS gRPC server exited unexpectedly");
                        }
                        Err(err) => {
                            error!(error = %format!("{err:#}"), "xDS gRPC server exited with error");
                            return Err(err).context("xDS gRPC server exited");
                        }
                    }
                }
            }
        }
        Command::Xds(args) => {
            info!("starting xds command");
            let db = db::connect(&args.database.database_url).await?;
            db::migrate(&db).await?;
            firewall::ensure_builtin_policy(&db, firewall::DEFAULT_POLICY_NAME).await?;
            let geo_lookup = geo::GeoIpLookup::default();
            let loaded_geo_prefixes = geo_lookup.rebuild_from_db(&db).await?;
            info!(
                geo_prefixes = loaded_geo_prefixes,
                "loaded country IP lookup database"
            );
            xds::serve(db, args, xds::DropEventHub::new(), geo_lookup).await
        }
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
        Command::Xdp { command } => match command {
            XdpCommand::Status(args) => {
                info!("starting xdp status command");
                xdp::dispatcher_status(args)
            }
            XdpCommand::Unload(args) => {
                info!("starting xdp unload command");
                xdp::dispatcher_unload(args)
            }
            XdpCommand::Replace(args) => {
                info!("starting xdp replace command");
                xdp::dispatcher_replace(args)
            }
        },
        Command::Policy { database, command } => match command {
            PolicyCommand::SeedExample(args) => {
                let db = db::connect(&database.database_url).await?;
                db::migrate(&db).await?;
                firewall::seed_example_policy(&db, args).await
            }
            PolicyCommand::Show(args) => {
                let db = db::connect(&database.database_url).await?;
                db::migrate(&db).await?;
                firewall::ensure_builtin_policy(&db, firewall::DEFAULT_POLICY_NAME).await?;
                firewall::show_policy(&db, args).await
            }
        },
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
