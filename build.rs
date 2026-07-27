use std::{
    env,
    error::Error,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=proto/xdp_firewall/xds/v1/control.proto");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: this build script sets PROTOC before prost/tonic reads it.
    unsafe {
        env::set_var("PROTOC", protoc);
    }
    tonic_prost_build::configure()
        .compile_protos(&["proto/xdp_firewall/xds/v1/control.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=frontend/dist/index.html");
    println!("cargo:rerun-if-changed=frontend/dist/assets");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let out_file = out_dir.join("frontend_assets.rs");
    let mut file = File::create(out_file)?;

    writeln!(
        file,
        "pub fn get(path: &str) -> Option<(&'static str, &'static [u8])> {{"
    )?;
    writeln!(file, "    match path {{")?;

    let assets_dir = Path::new("frontend/dist/assets");
    if assets_dir.is_dir() {
        let mut assets = fs::read_dir(assets_dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        assets.sort();

        for asset in assets {
            let route_path = format!(
                "assets/{}",
                asset
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("frontend asset filename must be valid utf-8")
            );
            let content_type = content_type_for(&asset);
            let include_path = asset
                .canonicalize()
                .unwrap_or(asset)
                .display()
                .to_string()
                .replace('\\', "\\\\")
                .replace('"', "\\\"");

            writeln!(
                file,
                "        {route_path:?} => Some(({content_type:?}, include_bytes!(\"{include_path}\").as_slice())),"
            )?;
        }
    } else {
        println!(
            "cargo:warning=frontend/dist/assets not found; run make frontend-build before cargo build"
        );
    }

    writeln!(file, "        _ => None,")?;
    writeln!(file, "    }}")?;
    writeln!(file, "}}")?;
    Ok(())
}

fn content_type_for(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("gif") => "image/gif",
        Some("ico") => "image/x-icon",
        Some("jpeg" | "jpg") => "image/jpeg",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json" | "map") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("webp") => "image/webp",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}
