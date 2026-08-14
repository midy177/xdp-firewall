use super::{XdpAttachOptions, XdpManager, XdpMapSizes};
use anyhow::Result;

impl XdpManager {
    pub fn attach(
        interface: Option<&str>,
        object_path: &str,
        program_name: &str,
        map_sizes: XdpMapSizes,
        attach_options: XdpAttachOptions,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let map_sizes = map_sizes.validate()?;
            let interface = resolve_interface_name(interface)?;
            return Ok(Self {
                inner: super::linux::LinuxXdpManager::attach(
                    &interface,
                    object_path,
                    program_name,
                    map_sizes,
                    attach_options,
                )?,
            });
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                interface,
                object_path,
                program_name,
                map_sizes,
                attach_options,
            );
            Ok(Self {})
        }
    }
}

pub fn resolve_interface_name(configured: Option<&str>) -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        return resolve_linux_interface_name(configured);
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(configured
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("noop")
            .to_string())
    }
}

#[cfg(target_os = "linux")]
fn resolve_linux_interface_name(configured: Option<&str>) -> Result<String> {
    use anyhow::{Context as _, bail};

    if let Some(interface) = configured.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(interface.to_string());
    }
    let routes = std::fs::read_to_string("/proc/net/route")
        .context("failed to read /proc/net/route for interface auto-detection")?;
    let mut candidates = routes
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            (fields.len() > 3 && fields[1] == "00000000").then(|| {
                let metric = fields
                    .get(6)
                    .and_then(|value| value.parse::<u32>().ok())
                    .unwrap_or(u32::MAX);
                (metric, fields[0].to_string())
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let Some((_, interface)) = candidates.into_iter().next() else {
        bail!("failed to auto-detect network interface from default route; pass --interface");
    };
    Ok(interface)
}
