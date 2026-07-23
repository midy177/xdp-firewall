use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};
use xdp_firewall::cli::{Cli, Command, PolicyCommand};
use xdp_firewall::{api, db, firewall, sync};

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
    let db = db::connect(&cli.database_url).await?;

    match cli.command {
        Command::Migrate => {
            info!("running database migrations");
            db::migrate(&db).await
        }
        Command::Api(args) => {
            info!(
                trusted_cidrs = args.trusted_cidrs.len(),
                "starting api command"
            );
            db::migrate(&db).await?;
            firewall::ensure_builtin_policy(&db, firewall::DEFAULT_POLICY_NAME).await?;
            firewall::ensure_configured_trusted_cidrs(
                &db,
                firewall::DEFAULT_POLICY_NAME,
                &args.trusted_cidrs,
            )
            .await?;
            api::serve(db, args).await
        }
        Command::Agent(args) => {
            info!("starting agent command");
            db::migrate(&db).await?;
            firewall::ensure_builtin_policy(&db, firewall::DEFAULT_POLICY_NAME).await?;
            sync::run_agent(db, args).await
        }
        Command::SyncOnce(args) => {
            info!("starting sync-once command");
            db::migrate(&db).await?;
            firewall::ensure_builtin_policy(&db, firewall::DEFAULT_POLICY_NAME).await?;
            sync::sync_once(db, args).await
        }
        Command::Policy { command } => match command {
            PolicyCommand::SeedExample(args) => {
                db::migrate(&db).await?;
                firewall::seed_example_policy(&db, args).await
            }
            PolicyCommand::Show(args) => {
                db::migrate(&db).await?;
                firewall::ensure_builtin_policy(&db, firewall::DEFAULT_POLICY_NAME).await?;
                firewall::show_policy(&db, args).await
            }
        },
    }
}
