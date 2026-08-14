use super::XdpStats;
use crate::policy::model::CompiledPolicy;
use anyhow::Result;
use std::net::IpAddr;

pub struct XdpManager {
    #[cfg(target_os = "linux")]
    pub(super) inner: super::linux::LinuxXdpManager,
}

impl XdpManager {
    pub fn apply(&mut self, policy: &CompiledPolicy) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            return self.inner.apply(policy);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = policy;
            Ok(())
        }
    }

    #[must_use]
    pub fn interface_name(&self) -> &str {
        #[cfg(target_os = "linux")]
        {
            return self.inner.interface_name();
        }
        #[cfg(not(target_os = "linux"))]
        {
            "noop"
        }
    }

    #[must_use]
    pub fn interface_ips(&self) -> Vec<IpAddr> {
        #[cfg(target_os = "linux")]
        {
            return self.inner.interface_ips();
        }
        #[cfg(not(target_os = "linux"))]
        {
            Vec::new()
        }
    }

    pub fn stats(&self) -> Result<XdpStats> {
        #[cfg(target_os = "linux")]
        {
            return self.inner.stats();
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(XdpStats::default())
        }
    }

    pub fn set_drop_monitor_enabled(&mut self, enabled: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            return self.inner.set_drop_monitor_enabled(enabled);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = enabled;
            Ok(())
        }
    }
}
