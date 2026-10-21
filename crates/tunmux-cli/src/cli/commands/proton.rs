use std::cmp::Ordering;
use std::time::Duration;

use crate::cli::{ProtonCommand, ProtonPortAction};
use tunmux_core::config::{self, AppConfig};
use tunmux_core::proton::handlers::*;
use tunmux_core::proton::models;
use tunmux_core::shared::latency;
use tunmux_core::shared::latency::{format_latency, latency_order};

pub async fn dispatch(command: ProtonCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        ProtonCommand::Login { username } => cmd_login(&username, config).await,
        ProtonCommand::Logout => logout(config).await,
        ProtonCommand::Info => cmd_info(config),
        ProtonCommand::Renew => cmd_renew(config).await,
        ProtonCommand::Servers {
            country,
            free,
            tag,
            sort,
        } => cmd_servers(country, free, tag, sort, config).await,
        ProtonCommand::Connect(args) => connect(args.into(), config).await,
        ProtonCommand::Ports { action } => cmd_ports(action, config).await,
        ProtonCommand::Disconnect { instance, all } => disconnect(instance, all, config),
    }
}

async fn cmd_login(username: &str, config: &AppConfig) -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Password: ")?;
    let mut two_factor = || Ok(Some(rpassword::prompt_password("2FA code: ")?));
    if let tunmux_core::api::LoginOutcome::LoggedIn { detail, .. } =
        login(username, &password, &mut two_factor, config).await?
    {
        println!("Logged in as {} ({})", username, detail);
    }
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

async fn cmd_renew(config: &AppConfig) -> anyhow::Result<()> {
    renew_certificate(config).await?;
    println!("Proton VPN certificate renewed.");
    Ok(())
}

async fn cmd_ports(action: ProtonPortAction, config: &AppConfig) -> anyhow::Result<()> {
    match action {
        ProtonPortAction::List { current, json } => cmd_ports_list(current, json),
        ProtonPortAction::Request {
            protocol,
            public_port,
            local_port,
            lifetime,
            no_daemon,
        } => {
            request_ports(
                &protocol,
                public_port,
                local_port,
                lifetime,
                no_daemon,
                config,
            )
            .await
        }
        ProtonPortAction::Renew { lifetime } => renew_ports(lifetime, config).await,
        ProtonPortAction::Release => release_ports(config).await,
        ProtonPortAction::Daemon {
            protocol,
            public_port,
            local_port,
            lifetime,
            renew_every,
            no_initial_request,
        } => {
            run_ports_daemon(
                &protocol,
                public_port,
                local_port,
                lifetime,
                renew_every,
                no_initial_request,
                config,
            )
            .await
        }
    }
}

fn cmd_ports_list(current_only: bool, json_output: bool) -> anyhow::Result<()> {
    let mut state = load_proton_port_forward_state()?;

    let now = current_unix_timestamp()? as u64;
    if current_only {
        let conn = require_active_proton_direct_connection()?;
        state.mappings.retain(|mapping| {
            mapping.instance_name == conn.instance_name
                && mapping.interface_name == conn.interface_name
                && mapping.expires_at_unix > now
        });
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&state.mappings)?);
        return Ok(());
    }

    if state.mappings.is_empty() {
        if current_only {
            println!("No current Proton forwarded ports.");
        } else {
            println!("No saved Proton forwarded ports.");
        }
        return Ok(());
    }

    state.mappings.sort_by(|a, b| {
        a.instance_name
            .cmp(&b.instance_name)
            .then_with(|| a.protocol.to_string().cmp(&b.protocol.to_string()))
            .then_with(|| a.public_port.cmp(&b.public_port))
    });

    println!(
        "{:<8} {:<8} {:<8} {:<10} {:<12} {:<10} Gateway",
        "Proto", "Public", "Local", "Lifetime", "ExpiresIn", "Instance"
    );
    println!("{}", "-".repeat(80));
    for mapping in &state.mappings {
        let expires_in = if mapping.expires_at_unix > now {
            format!("{}s", mapping.expires_at_unix - now)
        } else {
            "expired".to_string()
        };
        println!(
            "{:<8} {:<8} {:<8} {:<10} {:<12} {:<10} {}",
            mapping.protocol,
            mapping.public_port,
            mapping.local_port,
            mapping.lifetime_secs,
            expires_in,
            mapping.instance_name,
            mapping.gateway
        );
    }
    println!("\n{} mapping(s) saved", state.mappings.len());
    Ok(())
}

async fn cmd_servers(
    country: Option<String>,
    free: bool,
    tags: Vec<String>,
    sort: String,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let session: models::session::Session = config::load_session(PROVIDER, config)?;
    let mut servers = load_servers_cached_or_fetch(&session).await?;

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

    let requested_tags = parse_proton_feature_tags(&tags)?;
    apply_proton_feature_filters(&mut servers, &requested_tags);

    let sort_by_latency = sort == "latency";

    if sort_by_latency {
        let targets: Vec<(String, u16)> = servers
            .iter()
            .map(|server| {
                let host = server
                    .best_physical()
                    .map(|physical| physical.entry_ip.clone())
                    .unwrap_or_else(|| server.domain.clone());
                (host, 51820)
            })
            .collect();
        let latencies =
            latency::probe_endpoints_tcp(&targets, Duration::from_millis(800), 24).await;

        let mut rows: Vec<(models::server::LogicalServer, Option<Duration>)> =
            servers.into_iter().zip(latencies).collect();
        rows.sort_by(|a, b| {
            latency_order(&a.1, &b.1)
                .then_with(|| a.0.score.partial_cmp(&b.0.score).unwrap_or(Ordering::Equal))
                .then_with(|| a.0.name.cmp(&b.0.name))
        });

        if rows.is_empty() {
            println!("No servers match the given filters.");
            return Ok(());
        }

        println!(
            "{:<16} {:>2}  {:>5}  {:>5}  {:>4}  {:>8}  Features",
            "Name", "CC", "Load", "Score", "Tier", "Latency"
        );
        println!("{}", "-".repeat(74));

        for (server, latency) in &rows {
            let features = server.feature_tags();
            println!(
                "{:<16} {:>2}  {:>3}%  {:>5.1}  {:>4}  {:>8}  {}",
                server.name,
                server.exit_country,
                server.load,
                server.score,
                server.tier_enum(),
                format_latency(*latency),
                if features.is_empty() { "-" } else { &features }
            );
        }

        println!("\n{} servers listed", rows.len());
        return Ok(());
    }

    match sort.as_str() {
        "score" => {
            servers.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(Ordering::Equal));
        }
        "load" => {
            servers.sort_by(|a, b| a.load.cmp(&b.load).then_with(|| a.name.cmp(&b.name)));
        }
        "name" => {
            servers.sort_by(|a, b| a.name.cmp(&b.name));
        }
        _ => unreachable!(),
    }

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
