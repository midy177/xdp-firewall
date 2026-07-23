use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};
use xdp_firewall::cli::{Cli, Command, PolicyCommand};
use xdp_firewall::{api, db, firewall, sync, xds};

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

    match cli.command {
        Command::Migrate => {
            info!("running database migrations");
            let db = db::connect(&cli.database_url).await?;
            db::migrate(&db).await
        }
        Command::Api(args) => {
            info!(
                trusted_cidrs = args.trusted_cidrs.len(),
                "starting api command"
            );
            let db = db::connect(&cli.database_url).await?;
            db::migrate(&db).await?;
            firewall::ensure_builtin_policy(&db, firewall::DEFAULT_POLICY_NAME).await?;
            firewall::ensure_configured_trusted_cidrs(
                &db,
                firewall::DEFAULT_POLICY_NAME,
                &args.trusted_cidrs,
            )
            .await?;
            let xds_args = xdp_firewall::cli::XdsArgs {
                bind: args.xds_bind.clone(),
                push_interval_seconds: args.xds_push_interval_seconds,
                agent_token: args.agent_token.clone(),
            };
            let api_server = api::serve(db.clone(), args);
            let xds_server = xds::serve(db, xds_args);
            tokio::try_join!(api_server, xds_server)?;
            Ok(())
        }
        Command::Xds(args) => {
            info!("starting xds command");
            let db = db::connect(&cli.database_url).await?;
            db::migrate(&db).await?;
            firewall::ensure_builtin_policy(&db, firewall::DEFAULT_POLICY_NAME).await?;
            xds::serve(db, args).await
        }
        Command::Agent(args) => {
            info!("starting agent command");
            sync::run_agent(args).await
        }
        Command::SyncOnce(args) => {
            info!("starting sync-once command");
            sync::sync_once(args).await
        }
        Command::Policy { command } => match command {
            PolicyCommand::SeedExample(args) => {
                let db = db::connect(&cli.database_url).await?;
                db::migrate(&db).await?;
                firewall::seed_example_policy(&db, args).await
            }
            PolicyCommand::Show(args) => {
                let db = db::connect(&cli.database_url).await?;
                db::migrate(&db).await?;
                firewall::ensure_builtin_policy(&db, firewall::DEFAULT_POLICY_NAME).await?;
                firewall::show_policy(&db, args).await
            }
        },
    }
}
