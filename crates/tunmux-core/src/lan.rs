//! Keep physical connected LAN routes more specific than opted-in VPN routes.
use std::net::IpAddr;
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Prefix {
    network: u128,
    pub length: u8,
    v6: bool,
}
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl Prefix {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let (address, length) = text
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("CIDR prefix required"))?;
        let ip: IpAddr = address.parse()?;
        let length: u8 = length.parse()?;
        let (network, v6, width) = match ip {
            IpAddr::V4(ip) => (u32::from(ip) as u128, false, 32),
            IpAddr::V6(ip) => (u128::from(ip), true, 128),
        };
        anyhow::ensure!(length <= width, "invalid prefix length");
        Ok(Self {
            network: network & mask(width, length),
            length,
            v6,
        })
    }
    pub fn contains(self, other: Self) -> bool {
        self.v6 == other.v6
            && self.length <= other.length
            && other.network & mask(if self.v6 { 128 } else { 32 }, self.length) == self.network
    }
}
fn mask(width: u8, length: u8) -> u128 {
    if length == 0 {
        0
    } else {
        u128::MAX << (width - length)
            & if width == 128 {
                u128::MAX
            } else {
                u32::MAX as u128
            }
    }
}
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn vpn_routes(routes: &[String], lans: &[String]) -> anyhow::Result<Vec<String>> {
    let lans = lans
        .iter()
        .map(|s| Prefix::parse(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut result = Vec::new();
    for route in routes {
        let prefix = Prefix::parse(route)?;
        // A physical connected prefix already outranks broader VPN routes.
        // Omit VPN routes inside that prefix, which would override LAN access.
        if !lans.iter().any(|lan| lan.contains(prefix)) {
            result.push(route.clone());
        }
    }
    result.sort();
    result.dedup();
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_tunnel_stays_bounded() {
        let routes = vec![
            "0.0.0.0/1".into(),
            "128.0.0.0/1".into(),
            "::/1".into(),
            "8000::/1".into(),
        ];
        assert_eq!(
            vpn_routes(&routes, &["192.168.1.0/24".into(), "fd00::/64".into()])
                .unwrap()
                .len(),
            4
        );
    }
    #[test]
    fn specific_vpn_routes_cannot_override_lan() {
        let routes = vec![
            "10.0.0.0/8".into(),
            "10.1.2.0/24".into(),
            "10.1.2.42/32".into(),
            "fd00::1/128".into(),
        ];
        assert_eq!(
            vpn_routes(&routes, &["10.1.2.0/24".into(), "fd00::/64".into()]).unwrap(),
            ["10.0.0.0/8"]
        );
    }
    #[test]
    fn unrelated_routes_and_address_families_are_preserved() {
        let routes = vec!["192.0.2.0/24".into(), "2001:db8::/32".into()];
        assert_eq!(vpn_routes(&routes, &["10.0.0.0/8".into()]).unwrap(), routes);
        assert!(Prefix::parse("::/129").is_err());
    }
}
