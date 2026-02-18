use crate::api;
use crate::cli::ProtonCommand;
use crate::config::{self, AppConfig, Provider};
use crate::crypto;
use crate::error;
use crate::models;
use crate::wireguard;

const PROVIDER: Provider = Provider::Proton;
const INTERFACE_NAME: &str = "proton0";

pub async fn dispatch(command: ProtonCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        ProtonCommand::Login { username } => cmd_login(&username, config).await,
        ProtonCommand::Logout => cmd_logout(config).await,
        ProtonCommand::Info => cmd_info(config),
        ProtonCommand::Servers { country, free } => cmd_servers(country, free, config).await,
        ProtonCommand::Connect {
            server,
            country,
            p2p,
            backend,
        } => cmd_connect(server, country, p2p, backend, config).await,
        ProtonCommand::Disconnect => cmd_disconnect(),
    }
}

async fn cmd_login(username: &str, config: &AppConfig) -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Password: ")?;

    let mut client = api::http::ProtonClient::new()?;

    // SRP authentication
    let auth = api::auth::login(&mut client, username, &password).await?;

    // Handle 2FA if required
    if auth.two_factor.totp_required() {
        let code = rpassword::prompt_password("2FA code: ")?;
        api::auth::submit_2fa(&client, code.trim()).await?;
    }

    // Fetch VPN account info
    let vpn_info = api::vpn_info::fetch_vpn_info(&client).await?;

    // Generate Ed25519 keypair and derive X25519
    let keys = crypto::keys::VpnKeys::generate()?;

    // Fetch VPN certificate
    let cert = api::certificate::fetch_certificate(&client, &keys.ed25519_pk_pem()).await?;

    // Build and save session
    let session = models::session::Session {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        vpn_username: vpn_info.vpn.name,
        vpn_password: vpn_info.vpn.password,
        plan_name: vpn_info.vpn.plan_name,
        plan_title: vpn_info.vpn.plan_title,
        max_tier: vpn_info.vpn.max_tier,
        max_connections: vpn_info.vpn.max_connect,
        ed25519_private_key: keys.ed25519_sk_base64(),
        ed25519_public_key_pem: keys.ed25519_pk_pem(),
        wg_private_key: keys.wg_private_key(),
        wg_public_key: keys.wg_public_key(),
        fingerprint: keys.fingerprint(),
        certificate_pem: cert.certificate,
    };

    config::save_session(PROVIDER, &session, config)?;
    println!("Logged in as {} ({})", username, session.plan_title);
    Ok(())
}

async fn cmd_logout(config: &AppConfig) -> anyhow::Result<()> {
    // Disconnect if active
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME) {
        println!("Disconnecting active VPN connection...");
        disconnect_active()?;
    }

    config::delete_session(PROVIDER, config)?;
    println!("Logged out");
    Ok(())
}

fn cmd_info(config: &AppConfig) -> anyhow::Result<()> {
    let session: models::session::Session = config::load_session(PROVIDER, config)?;
    println!("Username:    {}", session.vpn_username);
    println!(
        "Plan:        {} ({})",
        session.plan_title, session.plan_name
    );
    println!("Tier:        {}", session.max_tier);
    println!("Connections: {}", session.max_connections);
    println!("Fingerprint: {}", &session.fingerprint[..16]);
    Ok(())
}

async fn cmd_servers(country: Option<String>, free: bool, config: &AppConfig) -> anyhow::Result<()> {
    let session: models::session::Session = config::load_session(PROVIDER, config)?;
    let client = api::http::ProtonClient::authenticated(&session.uid, &session.access_token)?;

    let resp = api::servers::fetch_server_list(&client).await?;
    let mut servers = resp.logical_servers;

    // Filter enabled servers
    servers.retain(|s| s.is_enabled());

    // Filter by country
    if let Some(ref cc) = country {
        let cc_upper = cc.to_uppercase();
        servers.retain(|s| s.exit_country == cc_upper);
    }

    // Filter free-tier only
    if free {
        servers.retain(|s| s.tier == 0);
    }

    // Sort by score (lower = better)
    servers.sort_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if servers.is_empty() {
        println!("No servers match the given filters.");
        return Ok(());
    }

    // Print header
    println!(
        "{:<16} {:>2}  {:>5}  {:>5}  {:>4}  Features",
        "Name", "CC", "Load", "Score", "Tier"
    );
    let separator = "-".repeat(60);
    println!("{separator}");

    for server in &servers {
        println!("{}", server);
    }

    println!("\n{} servers listed", servers.len());
    Ok(())
}

async fn cmd_connect(
    server_name: Option<String>,
    country: Option<String>,
    p2p: bool,
    backend_arg: Option<String>,
    config: &AppConfig,
) -> anyhow::Result<()> {
    // Check if already connected (any provider)
    if let Some(state) = wireguard::connection::ConnectionState::load()? {
        anyhow::bail!(
            "Already connected via {} ({}). Disconnect first.",
            state.provider,
            state.interface_name
        );
    }
    if wireguard::wg_quick::is_interface_active(INTERFACE_NAME) {
        anyhow::bail!("Already connected. Run `tunmux proton disconnect` first.");
    }

    let backend_str = backend_arg.as_deref()
        .unwrap_or(&config.general.backend);
    let backend = wireguard::backend::WgBackend::from_str_arg(backend_str)?;

    // Apply config defaults -- CLI flags override config
    let effective_country = country.or_else(|| config.proton.default_country.clone());

    let session: models::session::Session = config::load_session(PROVIDER, config)?;
    let client = api::http::ProtonClient::authenticated(&session.uid, &session.access_token)?;

    // Fetch servers
    let resp = api::servers::fetch_server_list(&client).await?;
    let mut servers = resp.logical_servers;

    // Filter enabled servers with WireGuard support
    servers.retain(|s| s.is_enabled() && s.best_physical().is_some());

    // Filter by user tier
    servers.retain(|s| s.tier <= session.max_tier);

    // Select server
    let server = if let Some(ref name) = server_name {
        servers
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| error::AppError::NoServerFound)?
    } else {
        // Apply filters
        if let Some(ref cc) = effective_country {
            let cc_upper = cc.to_uppercase();
            servers.retain(|s| s.exit_country == cc_upper);
        }
        if p2p {
            servers.retain(|s| s.has_feature(models::server::ServerFeature::P2P));
        }
        // Sort by score and pick best
        servers.sort_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        servers.first().ok_or(error::AppError::NoServerFound)?
    };

    let physical = server
        .best_physical()
        .ok_or(error::AppError::NoServerFound)?;

    println!("Connecting to {} ({})...", server.name, physical.entry_ip);

    // Restore keys from session
    let keys = crypto::keys::VpnKeys::from_base64(&session.ed25519_private_key)?;

    let server_pubkey = physical
        .x25519_public_key
        .as_deref()
        .ok_or_else(|| error::AppError::NoServerFound)?;

    let wg_private_key = keys.wg_private_key();
    let params = wireguard::config::WgConfigParams {
        private_key: &wg_private_key,
        addresses: &["10.2.0.2/32"],
        dns_servers: &["10.2.0.1"],
        server_public_key: server_pubkey,
        server_ip: &physical.entry_ip,
        server_port: 51820,
        preshared_key: None,
        allowed_ips: "0.0.0.0/0, ::/0",
    };

    match backend {
        wireguard::backend::WgBackend::WgQuick => {
            let wg_config = wireguard::config::generate_config(&params);
            wireguard::wg_quick::up(&wg_config, INTERFACE_NAME, PROVIDER)?;

            // Save connection state so disconnect knows which backend was used
            let state = wireguard::connection::ConnectionState {
                provider: PROVIDER.dir_name().to_string(),
                interface_name: INTERFACE_NAME.to_string(),
                backend,
                server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
                original_gateway_ip: None,
                original_gateway_iface: None,
                original_resolv_conf: None,
            };
            state.save()?;
        }
        wireguard::backend::WgBackend::Kernel => {
            wireguard::kernel::up(&params, INTERFACE_NAME, PROVIDER.dir_name())?;
        }
    }

    println!(
        "Connected to {} ({}) [backend: {}]",
        server.name, server.exit_country, backend
    );
    Ok(())
}

fn cmd_disconnect() -> anyhow::Result<()> {
    if !wireguard::wg_quick::is_interface_active(INTERFACE_NAME) {
        println!("Not connected.");
        return Ok(());
    }

    disconnect_active()?;
    println!("Disconnected");
    Ok(())
}

/// Tear down the active VPN, dispatching to the correct backend.
fn disconnect_active() -> anyhow::Result<()> {
    match wireguard::connection::ConnectionState::load()? {
        Some(state) => match state.backend {
            wireguard::backend::WgBackend::Kernel => {
                wireguard::kernel::down(&state)?;
            }
            wireguard::backend::WgBackend::WgQuick => {
                wireguard::wg_quick::down(INTERFACE_NAME, PROVIDER)?;
                wireguard::connection::ConnectionState::remove()?;
            }
        },
        // No state file -- fall back to wg-quick (legacy connections)
        None => {
            wireguard::wg_quick::down(INTERFACE_NAME, PROVIDER)?;
        }
    }
    Ok(())
}
