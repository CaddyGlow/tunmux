use std::time::Duration;

use crate::cli::{IvpnCommand, IvpnPaymentCommand};
use tunmux_core::config::{self, AppConfig};
use tunmux_core::ivpn::handlers::*;
use tunmux_core::shared::latency;
use tunmux_core::shared::latency::{format_latency, latency_order};
use tunmux_core::shared::util::{normalize_tags, short_key};

pub async fn dispatch(command: IvpnCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        IvpnCommand::Login { account, .. } => cmd_login(&account, config).await,
        IvpnCommand::CreateAccount { product, .. } => cmd_create_account(&product).await,
        IvpnCommand::Payment { action } => match action {
            IvpnPaymentCommand::Monero { account, duration } => {
                cmd_monero_payment(account.as_deref(), &duration, config).await
            }
        },
        IvpnCommand::Logout => logout(config).await,
        IvpnCommand::Info => cmd_info(config).await,
        IvpnCommand::Servers { country, tag, sort } => cmd_servers(country, tag, sort).await,
        IvpnCommand::Connect(args) => connect(args.into(), config).await,
        IvpnCommand::Disconnect { instance, all } => disconnect(instance, all, config),
    }
}

async fn cmd_create_account(product: &str) -> anyhow::Result<()> {
    let client = web_client()?;
    let product = normalize_create_account_product(product)?;
    let (account, _csrf_token) = create_account(&client, product).await?;
    save_account_id(&account.id)?;
    let plan = account
        .product
        .as_ref()
        .map(|p| p.name.as_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(CREATE_ACCOUNT_PRODUCT_STANDARD);

    println!("Created IVPN account {}", account.id);
    if !account.ref_id.is_empty() {
        println!("Reference ID: {}", account.ref_id);
    }
    println!("Plan:         {}", plan);
    if !account.is_active {
        println!("Status:       inactive");
    }
    Ok(())
}

async fn cmd_monero_payment(
    account_id: Option<&str>,
    duration: &str,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let client = web_client()?;
    let mut csrf_token = None;
    let duration = normalize_payment_duration(duration)?;
    let account_id = resolve_account_id(account_id, config)?;

    web_login(&client, &mut csrf_token, &account_id).await?;
    if csrf_token.is_none() {
        let _ = web_get_account(&client, &mut csrf_token).await;
    }

    let details = monero_payment_details(&client, &mut csrf_token, duration).await?;
    println!("Monero amount: {}", details.amount_rounded);
    println!("Monero atomic amount: {}", details.amount);
    println!("Monero address: {}", details.address);
    println!("Monero payment URI: {}", details.payment_uri);

    let items = payments(&client, &mut csrf_token, true, PAYMENT_METHOD_MONERO).await?;
    println!("Recent {} payments: {}", PAYMENT_METHOD_MONERO, items.len());
    Ok(())
}

async fn cmd_login(account_id: &str, config: &AppConfig) -> anyhow::Result<()> {
    let mut two_factor = || Ok(Some(rpassword::prompt_password("2FA code: ")?));
    if let tunmux_core::api::LoginOutcome::LoggedIn { detail, .. } =
        login(account_id, &mut two_factor, config).await?
    {
        println!("Logged in to IVPN account {}{}", account_id, detail);
    }
    Ok(())
}

async fn cmd_info(config: &AppConfig) -> anyhow::Result<()> {
    let mut session: IvpnSession = config::load_session(PROVIDER, config)?;

    let client = api_client()?;
    if let Ok(status) = session_status(&client, &session.session_token).await {
        if status.status == CODE_SUCCESS {
            if let Some(service) = status.service_status {
                session.account_active = service.is_active;
                session.account_active_until = if service.active_until > 0 {
                    Some(service.active_until)
                } else {
                    None
                };
            }
            if !status.device_name.is_empty() {
                session.device_name = status.device_name;
            }
            config::save_session(PROVIDER, &session, config)?;
        }
    }

    println!("Account:      {}", session.account_id);
    println!("Active:       {}", session.account_active);
    if let Some(unix_ts) = session.account_active_until {
        println!("Active until: {}", unix_ts);
    }
    println!(
        "Device:       {}",
        if session.device_name.is_empty() {
            "-".to_string()
        } else {
            session.device_name.clone()
        }
    );
    println!("WG local IP:  {}", session.wg_local_ip);
    println!("WG pubkey:    {}", short_key(&session.wg_public_key));
    Ok(())
}

async fn cmd_servers(
    country: Option<String>,
    tags: Vec<String>,
    sort: String,
) -> anyhow::Result<()> {
    let client = api_client()?;
    let manifest = load_manifest_cached_or_fetch(&client).await?;

    let mut rows: Vec<(&IvpnWireGuardServer, &IvpnWireGuardHost)> = Vec::new();
    for server in &manifest.wireguard {
        for host in &server.hosts {
            rows.push((server, host));
        }
    }

    if let Some(cc) = country {
        let cc_upper = cc.to_uppercase();
        rows.retain(|(s, _)| s.country_code.eq_ignore_ascii_case(&cc_upper));
    }

    let normalized_tags = normalize_tags(&tags);
    if !normalized_tags.is_empty() {
        rows.retain(|(server, host)| ivpn_matches_tags(server, host, &normalized_tags));
    }

    let sort_by_latency = sort == "latency";

    if sort_by_latency {
        let probe_port = choose_ivpn_port(&manifest.config.ports.wireguard);
        let targets: Vec<(String, u16)> = rows
            .iter()
            .map(|(_, host)| (host.host.clone(), probe_port))
            .collect();
        let latencies =
            latency::probe_endpoints_tcp(&targets, Duration::from_millis(800), 24).await;

        let mut latency_rows: Vec<((&IvpnWireGuardServer, &IvpnWireGuardHost), Option<Duration>)> =
            rows.into_iter().zip(latencies).collect();
        latency_rows.sort_by(|a, b| {
            latency_order(&a.1, &b.1)
                .then_with(|| {
                    a.0 .1
                        .load
                        .partial_cmp(&b.0 .1.load)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.0 .1.hostname.cmp(&b.0 .1.hostname))
        });

        if latency_rows.is_empty() {
            println!("No servers match the given filters.");
            return Ok(());
        }

        println!(
            "{:<24} {:>2}  {:<18} {:>6}  {:>8}  Host",
            "Gateway", "CC", "City", "Load", "Latency"
        );
        println!("{}", "-".repeat(102));
        for ((server, host), latency) in latency_rows {
            println!(
                "{:<24} {:>2}  {:<18} {:>5.1}%  {:>8}  {}",
                server.gateway,
                server.country_code,
                server.city,
                host.load,
                format_latency(latency),
                host.hostname
            );
        }
        return Ok(());
    }

    match sort.as_str() {
        "load" => {
            rows.sort_by(|a, b| {
                a.1.load
                    .partial_cmp(&b.1.load)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.1.hostname.cmp(&b.1.hostname))
            });
        }
        "name" => {
            rows.sort_by(|a, b| a.1.hostname.cmp(&b.1.hostname));
        }
        _ => unreachable!(),
    }

    if rows.is_empty() {
        println!("No servers match the given filters.");
        return Ok(());
    }

    println!(
        "{:<24} {:>2}  {:<18} {:>6}  Host",
        "Gateway", "CC", "City", "Load"
    );
    println!("{}", "-".repeat(90));
    for (server, host) in rows {
        println!(
            "{:<24} {:>2}  {:<18} {:>5.1}%  {}",
            server.gateway, server.country_code, server.city, host.load, host.hostname
        );
    }
    Ok(())
}
