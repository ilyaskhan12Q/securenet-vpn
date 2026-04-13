//! Cross-platform TUN device setup and I/O helpers.

use std::{net::Ipv4Addr, sync::Arc};

use ipnetwork::IpNetwork;
use tun::{self, AsyncDevice, Configuration};

use crate::error::{CoreError, Result};

/// Thin wrapper around a tun::AsyncDevice so we can share it across tasks.
#[derive(Clone)]
pub struct TunDevice {
    name: String,
    dev: Arc<AsyncDevice>,
}

impl TunDevice {
    /// Create and bring up a TUN device from interface config values.
    pub fn create(tun_name: &str, address_cidr: &str, mtu: u16) -> Result<Self> {
        let net: IpNetwork = address_cidr
            .parse()
            .map_err(|_| CoreError::InvalidCidr(address_cidr.to_string()))?;

        let (addr, netmask) = match net {
            IpNetwork::V4(v4) => (v4.ip(), prefix_to_netmask(v4.prefix())),
            IpNetwork::V6(_) => {
                return Err(CoreError::TunDevice(
                    "IPv6 interface addresses are not yet supported in tun config".to_string(),
                ))
            }
        };

        let mut config = Configuration::default();
        config
            .tun_name(tun_name)
            .address(addr)
            .netmask(netmask)
            .mtu(mtu)
            .up();

        // Linux requires root privileges for device creation.
        #[cfg(target_os = "linux")]
        {
            config.platform_config(|platform| {
                platform.ensure_root_privileges(true);
            });
        }

        let dev = tun::create_as_async(&config).map_err(|e| CoreError::TunDevice(e.to_string()))?;

        Ok(Self {
            name: tun_name.to_string(),
            dev: Arc::new(dev),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        self.dev
            .recv(buf)
            .await
            .map_err(|e| CoreError::TunDevice(e.to_string()))
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        self.dev
            .send(buf)
            .await
            .map_err(|e| CoreError::TunDevice(e.to_string()))
    }
}

fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = u32::MAX << (32 - prefix);
    Ipv4Addr::from(mask)
}
