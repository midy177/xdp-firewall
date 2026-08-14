use anyhow::{Context, Result, bail};
use tracing::{error, info};
use xdp_firewall::{
    cli::{ApiArgs, XdsArgs},
    control_plane::{api, xds},
    db,
    intelligence::geo,
    policy::{model::DEFAULT_POLICY_NAME, seed},
};

pub(crate) async fn run_api_command(args: ApiArgs) -> Result<()> {
    info!(
        api_configured_runtime_trusted_cidr_args = args.trusted_cidrs.len(),
        "starting api command"
    );
    let db = db::connect(&args.database.database_url).await?;
    db::migrate(&db).await?;
    seed::ensure_builtin_policy(&db, DEFAULT_POLICY_NAME).await?;
    let xds_args = xds_args_from_api(&args);
    let drop_events = xds::DropEventHub::new();
    let geo_lookup = load_geo_lookup(&db).await?;
    let api_server = api::serve(db.clone(), args, drop_events.clone(), geo_lookup.clone());
    let xds_server = xds::serve(db, xds_args, drop_events, geo_lookup);
    tokio::select! {
        result = api_server => handle_server_exit("API HTTP server", result),
        result = xds_server => handle_server_exit("xDS gRPC server", result),
    }
}

pub(crate) async fn run_xds_command(args: XdsArgs) -> Result<()> {
    info!("starting xds command");
    let db = db::connect(&args.database.database_url).await?;
    db::migrate(&db).await?;
    seed::ensure_builtin_policy(&db, DEFAULT_POLICY_NAME).await?;
    let geo_lookup = load_geo_lookup(&db).await?;
    xds::serve(db, args, xds::DropEventHub::new(), geo_lookup).await
}

fn xds_args_from_api(args: &ApiArgs) -> XdsArgs {
    XdsArgs {
        database: args.database.clone(),
        k8s: args.k8s.clone(),
        bind: args.xds_bind.clone(),
        push_interval_seconds: args.xds_push_interval_seconds,
        agent_token: args.agent_token.clone(),
        trusted_cidrs: args.trusted_cidrs.clone(),
    }
}

async fn load_geo_lookup(db: &sea_orm::DatabaseConnection) -> Result<geo::GeoIpLookup> {
    let geo_lookup = geo::GeoIpLookup::default();
    let loaded_geo_prefixes = geo_lookup.rebuild_from_db(db).await?;
    info!(
        geo_prefixes = loaded_geo_prefixes,
        "loaded country IP lookup database"
    );
    Ok(geo_lookup)
}

fn handle_server_exit(name: &str, result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => {
            error!("{name} exited unexpectedly without error");
            bail!("{name} exited unexpectedly");
        }
        Err(err) => {
            error!(error = %format!("{err:#}"), "{name} exited with error");
            Err(err).with_context(|| format!("{name} exited"))
        }
    }
}
