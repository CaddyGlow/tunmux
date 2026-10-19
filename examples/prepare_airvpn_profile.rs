//! Prepare a native-validation profile from the existing AirVPN login, without an API call.
#[cfg(all(feature = "airvpn", not(target_os = "android")))]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use tunmux::{
        airvpn::models::{AirManifest, AirSession},
        config::{self, Provider},
        wireguard::config::WgConfigParams,
    };
    let output = std::env::args()
        .nth(1)
        .context("usage: cargo run --example prepare_airvpn_profile -- <new-output.conf>")?;
    let config = config::load_config();
    let session: AirSession = config::load_session(Provider::AirVpn, &config)?;
    let manifest: AirManifest = config::load_manifest(Provider::AirVpn, "manifest.json")?;
    let key = if let Some(name) = &config.airvpn.default_device {
        session
            .keys
            .iter()
            .find(|k| k.name.eq_ignore_ascii_case(name))
    } else {
        session.keys.first()
    }
    .context("configured AirVPN device is missing")?;
    let country = config.default_country_for(Provider::AirVpn);
    let server = manifest
        .servers
        .iter()
        .filter(|s| country.is_none_or(|cc| s.country_code.eq_ignore_ascii_case(cc)))
        .min_by_key(|s| &s.name)
        .context("no server matching configured country")?;
    let mode = manifest
        .wg_modes
        .iter()
        .find(|m| m.protocol.eq_ignore_ascii_case("udp"))
        .context("no UDP WireGuard mode")?;
    let endpoint = server
        .ips_entry
        .get(mode.entry_index as usize)
        .or_else(|| server.ips_entry.first())
        .context("server endpoint missing")?;
    let addresses: Vec<_> = [key.wg_ipv4.as_str(), key.wg_ipv6.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let dns: Vec<_> = [key.wg_dns_ipv4.as_str(), key.wg_dns_ipv6.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let params = WgConfigParams {
        private_key: &key.wg_private_key,
        addresses: &addresses,
        dns_servers: &dns,
        mtu: Some(1320),
        server_public_key: &session.wg_public_key,
        server_ip: endpoint,
        server_port: mode.port,
        preshared_key: if key.wg_preshared.is_empty() {
            None
        } else {
            Some(&key.wg_preshared)
        },
        allowed_ips: "0.0.0.0/0, ::/0",
    };
    let text = tunmux::wireguard::config::generate_config(&params);
    tunmux::wireguard::config::parse_config(&text)?;
    let path = std::path::Path::new(&output);
    let parent = path.parent().context("output needs a parent directory")?;
    if !parent.exists() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    println!(
        "Prepared {} for AirVPN server {} (private mode 0600)",
        path.display(),
        server.name
    );
    Ok(())
}
#[cfg(not(all(feature = "airvpn", not(target_os = "android"))))]
fn main() {
    eprintln!("requires the airvpn feature on a desktop target");
    std::process::exit(1);
}
