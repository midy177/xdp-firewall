use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};
use xdp_firewall::cli::{Cli, Command, PolicyCommand};
use xdp_firewall::{api, db, firewall, sync};

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let db = db::connect(&cli.database_url).await?;

    match cli.command {
        Command::Migrate => db::migrate(&db).await,
        Command::Api(args) => {
            db::migrate(&db).await?;
            firewall::ensure_builtin_policy(&db, "edge").await?;
            api::serve(db, args).await
        }
        Command::Agent(args) => {
            db::migrate(&db).await?;
            firewall::ensure_builtin_policy(&db, &args.policy).await?;
            sync::run_agent(db, args).await
        }
        Command::SyncOnce(args) => {
            db::migrate(&db).await?;
            firewall::ensure_builtin_policy(&db, &args.policy).await?;
            sync::sync_once(db, args).await
        }
        Command::Policy { command } => match command {
            PolicyCommand::SeedExample(args) => {
                db::migrate(&db).await?;
                firewall::seed_example_policy(&db, args).await
            }
            PolicyCommand::Show(args) => {
                db::migrate(&db).await?;
                firewall::ensure_builtin_policy(&db, &args.name).await?;
                firewall::show_policy(&db, args).await
            }
        },
    }
}
