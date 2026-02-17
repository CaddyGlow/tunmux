mod api;
mod cli;
mod config;
mod crypto;
mod error;
mod models;
mod wireguard;

use clap::Parser;
use tracing::error;

use cli::{Cli, Command};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .without_time()
        .init();

    if let Err(e) = run(cli.command).await {
        error!("{}", e);
        std::process::exit(1);
    }
}

async fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Login { username } => cmd_login(&username).await,
        Command::Logout => cmd_logout().await,
        Command::Info => cmd_info(),
        Command::Servers { country, free } => cmd_servers(country, free).await,
        Command::Connect {
            server,
            country,
            p2p,
        } => cmd_connect(server, country, p2p).await,
        Command::Disconnect => cmd_disconnect(),
    }
}

async fn cmd_login(username: &str) -> anyhow::Result<()> {
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

    config::save_session(&session)?;
    println!("Logged in as {} ({})", username, session.plan_title);
    Ok(())
}

async fn cmd_logout() -> anyhow::Result<()> {
    // Disconnect if active
    if wireguard::wg_quick::is_active() {
        println!("Disconnecting active VPN connection...");
        wireguard::wg_quick::down()?;
    }

    config::delete_session()?;
    println!("Logged out");
    Ok(())
}

fn cmd_info() -> anyhow::Result<()> {
    let session = config::load_session()?;
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

async fn cmd_servers(country: Option<String>, free: bool) -> anyhow::Result<()> {
    let session = config::load_session()?;
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
) -> anyhow::Result<()> {
    // Check if already connected
    if wireguard::wg_quick::is_active() {
        anyhow::bail!("Already connected. Run `protonvpn disconnect` first.");
    }

    let session = config::load_session()?;
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
        if let Some(ref cc) = country {
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

    // Generate WireGuard config
    let server_pubkey = physical
        .x25519_public_key
        .as_deref()
        .ok_or_else(|| error::AppError::NoServerFound)?;

    let wg_config = wireguard::config::generate_config(&wireguard::config::WgConfigParams {
        private_key: &keys.wg_private_key(),
        server_public_key: server_pubkey,
        server_ip: &physical.entry_ip,
        server_port: 51820,
    });

    // Write config and bring up interface
    wireguard::wg_quick::up(&wg_config)?;
    println!("Connected to {} ({})", server.name, server.exit_country);
    Ok(())
}

fn cmd_disconnect() -> anyhow::Result<()> {
    if !wireguard::wg_quick::is_active() {
        println!("Not connected.");
        return Ok(());
    }

    wireguard::wg_quick::down()?;
    println!("Disconnected");
    Ok(())
}
