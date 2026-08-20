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
        standby = args.standby,
        "starting api command"
    );
    let db = db::connect(&args.database.database_url).await?;
    if args.standby {
        info!("standby read-only mode: skipping database migrations and builtin policy seed");
    } else {
        db::migrate(&db).await?;
        seed::ensure_builtin_policy(&db, DEFAULT_POLICY_NAME).await?;
    }
    let tls = xds::build_control_plane_tls(&args.xds_tls)?;
    let api_tls = resolve_api_tls(args.api_tls, &tls)?;
    let xds_args = xds_args_from_api(&args);
    let drop_events = xds::DropEventHub::new();
    let geo_lookup = load_geo_lookup(&db).await?;
    let api_server = api::serve(
        db.clone(),
        args,
        drop_events.clone(),
        geo_lookup.clone(),
        api_tls,
    );
    let xds_server = xds::serve(db, xds_args, drop_events, geo_lookup, tls);
    tokio::select! {
        result = api_server => handle_server_exit("API HTTP server", result),
        result = xds_server => handle_server_exit("xDS gRPC server", result),
    }
}

pub(crate) async fn run_xds_command(args: XdsArgs) -> Result<()> {
    info!(standby = args.standby, "starting xds command");
    let db = db::connect(&args.database.database_url).await?;
    if args.standby {
        info!("standby read-only mode: skipping database migrations and builtin policy seed");
    } else {
        db::migrate(&db).await?;
        seed::ensure_builtin_policy(&db, DEFAULT_POLICY_NAME).await?;
    }
    let tls = xds::build_control_plane_tls(&args.xds_tls)?;
    let geo_lookup = load_geo_lookup(&db).await?;
    xds::serve(db, args, xds::DropEventHub::new(), geo_lookup, tls).await
}

fn resolve_api_tls(
    api_tls: bool,
    tls: &Option<xds::ControlPlaneTls>,
) -> Result<Option<api::ApiTlsMaterial>> {
    if !api_tls {
        return Ok(None);
    }
    let tls = tls.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "--api-tls requires xDS TLS material; configure --xds-tls-cert/--xds-tls-key or --xds-tls-auto"
        )
    })?;
    Ok(Some(api::ApiTlsMaterial {
        cert_path: tls.server_cert_path.clone(),
        key_path: tls.server_key_path.clone(),
    }))
}

fn xds_args_from_api(args: &ApiArgs) -> XdsArgs {
    XdsArgs {
        database: args.database.clone(),
        k8s: args.k8s.clone(),
        bind: args.xds_bind.clone(),
        push_interval_seconds: args.xds_push_interval_seconds,
        agent_token: args.agent_token.clone(),
        trusted_cidrs: args.trusted_cidrs.clone(),
        standby: args.standby,
        xds_tls: args.xds_tls.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_tls_disabled_by_default() {
        assert!(
            resolve_api_tls(false, &None)
                .expect("disabled api TLS must not error")
                .is_none()
        );
    }

    #[test]
    fn api_tls_requires_xds_tls_material() {
        let err =
            resolve_api_tls(true, &None).expect_err("--api-tls without xDS TLS material must fail");
        assert!(format!("{err:#}").contains("--api-tls"));
    }

    #[test]
    fn api_tls_reuses_xds_server_material_paths() {
        let tls = xds::ControlPlaneTls {
            server_tls: tonic::transport::ServerTlsConfig::new(),
            mutual_tls: true,
            server_cert_path: std::path::PathBuf::from("server.pem"),
            server_key_path: std::path::PathBuf::from("server.key"),
        };
        let material = resolve_api_tls(true, &Some(tls))
            .expect("api TLS with xDS material must not error")
            .expect("api TLS must resolve");
        assert_eq!(material.cert_path, std::path::PathBuf::from("server.pem"));
        assert_eq!(material.key_path, std::path::PathBuf::from("server.key"));
    }
}
