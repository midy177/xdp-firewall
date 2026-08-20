use crate::cli::XdsTlsServerArgs;
use anyhow::{Context, Result, bail};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::path::{Path, PathBuf};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tracing::info;

pub struct ControlPlaneTls {
    pub server_tls: ServerTlsConfig,
    pub mutual_tls: bool,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
}

impl std::fmt::Debug for ControlPlaneTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneTls")
            .field("mutual_tls", &self.mutual_tls)
            .field("server_cert_path", &self.server_cert_path)
            .field("server_key_path", &self.server_key_path)
            .finish_non_exhaustive()
    }
}

pub fn build_control_plane_tls(args: &XdsTlsServerArgs) -> Result<Option<ControlPlaneTls>> {
    if args.xds_tls_auto {
        ensure_no_explicit_material(args)?;
        build_auto_tls(args).map(Some)
    } else {
        build_file_tls(args)
    }
}

fn ensure_no_explicit_material(args: &XdsTlsServerArgs) -> Result<()> {
    if args.xds_tls_cert.is_some() || args.xds_tls_key.is_some() || args.xds_tls_client_ca.is_some()
    {
        bail!(
            "--xds-tls-auto cannot be combined with --xds-tls-cert/--xds-tls-key/--xds-tls-client-ca; choose auto-generated or explicit PEM files"
        );
    }
    Ok(())
}

fn build_file_tls(args: &XdsTlsServerArgs) -> Result<Option<ControlPlaneTls>> {
    let cert = args.xds_tls_cert.as_ref();
    let key = args.xds_tls_key.as_ref();
    let client_ca = args.xds_tls_client_ca.as_ref();
    if cert.is_none() && key.is_none() && client_ca.is_none() {
        return Ok(None);
    }
    let (cert, key) = match (cert, key) {
        (Some(cert), Some(key)) => (cert, key),
        (Some(_), None) => bail!(
            "--xds-tls-cert is set without --xds-tls-key; configure both to enable TLS or leave both unset"
        ),
        (None, Some(_)) => bail!(
            "--xds-tls-key is set without --xds-tls-cert; configure both to enable TLS or leave both unset"
        ),
        (None, None) => bail!(
            "--xds-tls-client-ca requires --xds-tls-cert and --xds-tls-key; configure server TLS before requiring client certificates"
        ),
    };
    let identity = Identity::from_pem(read_pem(cert)?, read_pem(key)?);
    let mut tls = ServerTlsConfig::new().identity(identity);
    let mutual_tls = match client_ca {
        Some(ca) => {
            tls = tls.client_ca_root(Certificate::from_pem(read_pem(ca)?));
            true
        }
        None => false,
    };
    Ok(Some(ControlPlaneTls {
        server_tls: tls,
        mutual_tls,
        server_cert_path: cert.clone(),
        server_key_path: key.clone(),
    }))
}

struct AutoTlsFiles {
    ca_cert: PathBuf,
    ca_key: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl AutoTlsFiles {
    fn new(dir: &Path) -> Self {
        Self {
            ca_cert: dir.join("ca.pem"),
            ca_key: dir.join("ca.key"),
            server_cert: dir.join("server.pem"),
            server_key: dir.join("server.key"),
            client_cert: dir.join("client.pem"),
            client_key: dir.join("client.key"),
        }
    }

    fn existing(&self) -> Vec<&Path> {
        [
            self.ca_cert.as_path(),
            self.ca_key.as_path(),
            self.server_cert.as_path(),
            self.server_key.as_path(),
            self.client_cert.as_path(),
            self.client_key.as_path(),
        ]
        .into_iter()
        .filter(|path| path.exists())
        .collect()
    }
}

fn build_auto_tls(args: &XdsTlsServerArgs) -> Result<ControlPlaneTls> {
    let dir = args.xds_tls_dir.as_path();
    let files = AutoTlsFiles::new(dir);
    let existing = files.existing();
    if existing.len() == 6 {
        info!(
            dir = %dir.display(),
            "reusing auto-generated xDS TLS material; agents keep using ca.pem plus client.pem/client.key from this directory"
        );
    } else if !existing.is_empty() {
        let missing = [
            files.ca_cert.as_path(),
            files.ca_key.as_path(),
            files.server_cert.as_path(),
            files.server_key.as_path(),
            files.client_cert.as_path(),
            files.client_key.as_path(),
        ]
        .into_iter()
        .filter(|path| !path.exists())
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
        bail!(
            "--xds-tls-dir {} has partial TLS material; missing {missing}. Remove the directory to regenerate the full set or restore the missing files",
            dir.display()
        );
    } else {
        generate_auto_tls(dir, &files, args)?;
    }
    let identity = Identity::from_pem(read_pem(&files.server_cert)?, read_pem(&files.server_key)?);
    let server_tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(Certificate::from_pem(read_pem(&files.ca_cert)?));
    Ok(ControlPlaneTls {
        server_tls,
        mutual_tls: true,
        server_cert_path: files.server_cert,
        server_key_path: files.server_key,
    })
}

fn generate_auto_tls(dir: &Path, files: &AutoTlsFiles, args: &XdsTlsServerArgs) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create xDS TLS directory {}", dir.display()))?;
    let sans = sanitize_sans(&args.xds_tls_san);

    let ca_key = KeyPair::generate().context("failed to generate xDS TLS CA key")?;
    let ca_key_pem = ca_key.serialize_pem();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "xdp-firewall-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    set_validity(&mut ca_params, args.xds_tls_validity_days);
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key)
        .context("failed to self-sign xDS TLS CA")?;
    write_pem(&files.ca_cert, ca.pem(), false)?;
    write_pem(&files.ca_key, ca_key_pem, true)?;

    let server_key = KeyPair::generate().context("failed to generate xDS server key")?;
    let mut server_params = CertificateParams::new(sans.clone())
        .context("failed to build xDS server certificate parameters")?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "xdp-firewall-control-plane");
    set_validity(&mut server_params, args.xds_tls_validity_days);
    let server_cert = server_params
        .signed_by(&server_key, &ca)
        .context("failed to sign xDS server certificate")?;
    write_pem(&files.server_cert, server_cert.pem(), false)?;
    write_pem(&files.server_key, server_key.serialize_pem(), true)?;

    let client_key = KeyPair::generate().context("failed to generate xDS agent client key")?;
    let mut client_params = CertificateParams::default();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "xdp-agent");
    set_validity(&mut client_params, args.xds_tls_validity_days);
    let client_cert = client_params
        .signed_by(&client_key, &ca)
        .context("failed to sign xDS agent client certificate")?;
    write_pem(&files.client_cert, client_cert.pem(), false)?;
    write_pem(&files.client_key, client_key.serialize_pem(), true)?;

    info!(
        dir = %dir.display(),
        sans = %sans.join(","),
        "generated auto-signed xDS mTLS material; distribute ca.pem plus client.pem/client.key to agents (single-host agents can reference this directory directly)"
    );
    Ok(())
}

fn sanitize_sans(sans: &[String]) -> Vec<String> {
    let cleaned: Vec<String> = sans
        .iter()
        .map(|san| san.trim().to_string())
        .filter(|san| !san.is_empty())
        .collect();
    if cleaned.is_empty() {
        vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ]
    } else {
        cleaned
    }
}

fn set_validity(params: &mut CertificateParams, days: i64) {
    use chrono::Datelike;
    let now = chrono::Utc::now();
    let later = now + chrono::Duration::days(days);
    params.not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
    params.not_after = rcgen::date_time_ymd(later.year(), later.month() as u8, later.day() as u8);
}

fn write_pem(path: &Path, contents: String, secret: bool) -> Result<()> {
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write xDS TLS PEM file {}", path.display()))?;
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict permissions on {}", path.display()))?;
    }
    Ok(())
}

fn read_pem(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path)
        .with_context(|| format!("failed to read xDS TLS PEM file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_args(
        cert: Option<&str>,
        key: Option<&str>,
        client_ca: Option<&str>,
    ) -> XdsTlsServerArgs {
        XdsTlsServerArgs {
            xds_tls_cert: cert.map(PathBuf::from),
            xds_tls_key: key.map(PathBuf::from),
            xds_tls_client_ca: client_ca.map(PathBuf::from),
            xds_tls_auto: false,
            xds_tls_dir: PathBuf::from("/tmp/xdp-firewall-tls-test-unused"),
            xds_tls_san: Vec::new(),
            xds_tls_validity_days: 36_500,
        }
    }

    fn auto_args(dir: &Path, sans: Vec<String>) -> XdsTlsServerArgs {
        XdsTlsServerArgs {
            xds_tls_cert: None,
            xds_tls_key: None,
            xds_tls_client_ca: None,
            xds_tls_auto: true,
            xds_tls_dir: dir.to_path_buf(),
            xds_tls_san: sans,
            xds_tls_validity_days: 36_500,
        }
    }

    #[test]
    fn tls_disabled_by_default() {
        assert!(
            build_control_plane_tls(&file_args(None, None, None))
                .expect("default args must not error")
                .is_none()
        );
    }

    #[test]
    fn cert_without_key_is_rejected() {
        let err = build_control_plane_tls(&file_args(Some("cert.pem"), None, None))
            .expect_err("cert without key must fail");
        assert!(format!("{err:#}").contains("--xds-tls-cert"));
    }

    #[test]
    fn key_without_cert_is_rejected() {
        let err = build_control_plane_tls(&file_args(None, Some("key.pem"), None))
            .expect_err("key without cert must fail");
        assert!(format!("{err:#}").contains("--xds-tls-key"));
    }

    #[test]
    fn client_ca_without_server_tls_is_rejected() {
        let err = build_control_plane_tls(&file_args(None, None, Some("ca.pem")))
            .expect_err("client CA without server TLS must fail");
        assert!(format!("{err:#}").contains("--xds-tls-client-ca"));
    }

    #[test]
    fn auto_conflicts_with_explicit_material() {
        let mut args = auto_args(Path::new("/tmp/unused"), Vec::new());
        args.xds_tls_cert = Some(PathBuf::from("cert.pem"));
        let err =
            build_control_plane_tls(&args).expect_err("auto plus explicit material must fail");
        assert!(format!("{err:#}").contains("--xds-tls-auto"));
    }

    #[test]
    fn auto_generates_full_material_and_reuses_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let args = auto_args(dir.path(), vec!["127.0.0.1".to_string()]);
        let tls = build_control_plane_tls(&args)
            .expect("auto TLS generation must succeed")
            .expect("auto mode always enables TLS");
        assert!(tls.mutual_tls);
        assert!(tls.server_cert_path.is_file());
        assert!(tls.server_key_path.is_file());
        for name in [
            "ca.pem",
            "ca.key",
            "server.pem",
            "server.key",
            "client.pem",
            "client.key",
        ] {
            assert!(dir.path().join(name).is_file(), "missing {name}");
        }
        let ca_before = std::fs::read(dir.path().join("ca.pem")).expect("ca.pem");
        let client_before = std::fs::read(dir.path().join("client.pem")).expect("client.pem");
        build_control_plane_tls(&args)
            .expect("second auto TLS build must succeed")
            .expect("auto mode always enables TLS");
        let ca_after = std::fs::read(dir.path().join("ca.pem")).expect("ca.pem");
        let client_after = std::fs::read(dir.path().join("client.pem")).expect("client.pem");
        assert_eq!(ca_before, ca_after, "existing CA must be reused");
        assert_eq!(
            client_before, client_after,
            "existing client cert must be reused"
        );
    }

    #[test]
    fn auto_rejects_partial_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("ca.pem"), b"partial").expect("write partial file");
        let args = auto_args(dir.path(), Vec::new());
        let err = build_control_plane_tls(&args).expect_err("partial material must fail");
        assert!(format!("{err:#}").contains("partial TLS material"));
    }

    #[test]
    fn default_sans_are_filled_when_empty() {
        assert_eq!(
            sanitize_sans(&["  ".to_string(), String::new()]),
            vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string()
            ]
        );
        assert_eq!(
            sanitize_sans(&["control.example".to_string(), " 10.0.0.5 ".to_string()]),
            vec!["control.example".to_string(), "10.0.0.5".to_string()]
        );
    }

    #[test]
    fn validity_days_default_to_100_years_and_are_bounded() {
        use clap::Parser as _;
        let cli = crate::cli::Cli::try_parse_from([
            "xdp-firewall",
            "xds",
            "--database-url",
            "sqlite://unused.db",
        ])
        .expect("xds command must parse");
        let crate::cli::Command::Xds(args) = cli.command else {
            panic!("expected xds command");
        };
        assert_eq!(args.xds_tls.xds_tls_validity_days, 36_500);
        assert!(
            crate::cli::Cli::try_parse_from([
                "xdp-firewall",
                "xds",
                "--database-url",
                "sqlite://unused.db",
                "--xds-tls-validity-days",
                "0",
            ])
            .is_err(),
            "zero validity must be rejected"
        );
    }
}
