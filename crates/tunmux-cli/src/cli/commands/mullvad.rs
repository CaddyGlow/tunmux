use std::io::Write;
use std::time::Duration;

use anyhow::Context;

use crate::cli::{MullvadCommand, MullvadPaymentCommand};
use tunmux_core::config::{self, AppConfig};
use tunmux_core::mullvad::handlers::*;
use tunmux_core::shared::latency;
use tunmux_core::shared::latency::{format_latency, latency_order};
use tunmux_core::shared::util::{normalize_tags, short_key};

pub async fn dispatch(command: MullvadCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        MullvadCommand::Login { account, force } => cmd_login(&account, force, config).await,
        MullvadCommand::CreateAccount { json, force } => {
            cmd_create_account(json, force, config).await
        }
        MullvadCommand::Payment { action } => match action {
            MullvadPaymentCommand::Monero { account, json } => {
                cmd_monero_payment(account, json, config).await
            }
        },
        MullvadCommand::Logout => logout(config).await,
        MullvadCommand::Info => cmd_info(config).await,
        MullvadCommand::Servers { country, tag, sort } => cmd_servers(country, tag, sort).await,
        MullvadCommand::Connect(args) => connect(args.into(), config).await,
        MullvadCommand::Disconnect { instance, all } => disconnect(instance, all, config),
    }
}

async fn cmd_create_account(json: bool, force: bool, config: &AppConfig) -> anyhow::Result<()> {
    confirm_create_account_allowed(force)?;
    let client = api_client()?;
    let account_number = create_account(&client).await?;
    save_account_id(&account_number)?;

    let session = login_with_client(&client, &account_number, config)
        .await
        .with_context(|| {
            format!(
                "created Mullvad account {}, but failed to register device/login",
                account_number
            )
        })?;

    if json {
        let output = serde_json::json!({
            "account_number": session.account_number,
            "account_id": session.account_id,
            "account_expiry": session.account_expiry,
            "device": {
                "id": session.device_id,
                "name": session.device_name,
                "public_key": session.device_public_key,
            },
            "wireguard": {
                "public_key": session.wg_public_key,
                "ipv4_address": session.ipv4_address,
                "ipv6_address": session.ipv6_address,
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Created Mullvad account {}", account_number);
        println!(
            "Logged in to Mullvad account {} (device: {})",
            account_number, session.device_name
        );
    }

    Ok(())
}

async fn cmd_monero_payment(
    account: Option<String>,
    json: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let account_number = resolve_account_id(account.as_deref(), config)?;

    let client = mullvad_web_client()?;
    mullvad_web_login(&client, &account_number).await?;
    let payment = fetch_monero_payment(&client).await?;

    if json {
        let output = serde_json::json!({
            "account_number": account_number,
            "monthly_price": payment.monthly_price,
            "monthly_price_eur": payment.monthly_price_eur,
            "address": payment.address,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Account:           {}", account_number);
        println!("Monero monthly:    {}", payment.monthly_price);
        println!("Monthly EUR price: {}", payment.monthly_price_eur);
        println!("Address:           {}", payment.address);
    }

    Ok(())
}

async fn cmd_login(account_number: &str, force: bool, config: &AppConfig) -> anyhow::Result<()> {
    confirm_login_allowed(account_number, force)?;
    let client = api_client()?;
    let session = login_with_client(&client, account_number, config).await?;

    println!(
        "Logged in to Mullvad account {} (device: {})",
        account_number, session.device_name
    );
    Ok(())
}

async fn cmd_info(config: &AppConfig) -> anyhow::Result<()> {
    let mut session: MullvadSession = config::load_session(PROVIDER, config)?;

    let client = api_client()?;
    if let Ok(access_token) = fetch_access_token(&client, &session.account_number).await {
        if let Ok(account) = fetch_account(&client, &access_token).await {
            session.account_id = account.id;
            session.account_expiry = account.expiry;
            config::save_session(PROVIDER, &session, config)?;
        }
    }

    println!("Account:      {}", session.account_number);
    println!("Account ID:   {}", session.account_id);
    println!("Expiry:       {}", session.account_expiry);
    println!(
        "Device:       {} ({})",
        session.device_name, session.device_id
    );
    println!("WG pubkey:    {}", short_key(&session.wg_public_key));
    println!("Device pubkey: {}", short_key(&session.device_public_key));
    Ok(())
}

async fn cmd_servers(
    country: Option<String>,
    tags: Vec<String>,
    sort: String,
) -> anyhow::Result<()> {
    let client = api_client()?;
    let manifest = load_manifest_cached_or_fetch(&client).await?;
    let mut relays: Vec<&MullvadRelay> = manifest
        .wireguard
        .relays
        .iter()
        .filter(|r| r.active)
        .collect();

    if let Some(cc) = country {
        let cc_upper = cc.to_uppercase();
        relays.retain(|r| country_code_from_location(&r.location) == cc_upper);
    }

    let normalized_tags = normalize_tags(&tags);
    if !normalized_tags.is_empty() {
        relays.retain(|relay| mullvad_relay_matches_tags(&manifest, relay, &normalized_tags));
    }

    let sort_by_latency = sort == "latency";

    if sort_by_latency {
        let probe_port = choose_mullvad_port(&manifest.wireguard.port_ranges);
        let targets: Vec<(String, u16)> = relays
            .iter()
            .map(|relay| (relay.ipv4_addr_in.clone(), probe_port))
            .collect();
        let latencies =
            latency::probe_endpoints_tcp(&targets, Duration::from_millis(800), 24).await;

        let mut rows: Vec<(&MullvadRelay, Option<Duration>)> =
            relays.into_iter().zip(latencies).collect();
        rows.sort_by(|a, b| {
            latency_order(&a.1, &b.1).then_with(|| a.0.hostname.cmp(&b.0.hostname))
        });

        if rows.is_empty() {
            println!("No servers match the given filters.");
            return Ok(());
        }

        println!(
            "{:<20} {:>2}  {:<20} {:<14} {:>8}  Ingress",
            "Hostname", "CC", "City", "Provider", "Latency"
        );
        println!("{}", "-".repeat(94));

        for (relay, latency) in rows {
            let cc = country_code_from_location(&relay.location);
            let city = manifest
                .locations
                .get(&relay.location)
                .map(|l| l.city.as_str())
                .unwrap_or("-");
            println!(
                "{:<20} {:>2}  {:<20} {:<14} {:>8}  {}",
                relay.hostname,
                cc,
                city,
                relay.provider,
                format_latency(latency),
                relay.ipv4_addr_in
            );
        }

        return Ok(());
    }

    relays.sort_by(|a, b| a.hostname.cmp(&b.hostname));

    if relays.is_empty() {
        println!("No servers match the given filters.");
        return Ok(());
    }

    println!(
        "{:<20} {:>2}  {:<20} {:<14} Ingress",
        "Hostname", "CC", "City", "Provider"
    );
    println!("{}", "-".repeat(84));

    for relay in relays {
        let cc = country_code_from_location(&relay.location);
        let city = manifest
            .locations
            .get(&relay.location)
            .map(|l| l.city.as_str())
            .unwrap_or("-");
        println!(
            "{:<20} {:>2}  {:<20} {:<14} {}",
            relay.hostname, cc, city, relay.provider, relay.ipv4_addr_in
        );
    }

    Ok(())
}

fn confirm_create_account_allowed(force: bool) -> anyhow::Result<()> {
    let existing = load_saved_account_id()?;
    confirm_account_overwrite(
        force,
        existing.as_deref(),
        None,
        "create a new Mullvad account",
    )
}

fn confirm_login_allowed(account_number: &str, force: bool) -> anyhow::Result<()> {
    let existing = load_saved_account_id()?;
    confirm_account_overwrite(
        force,
        existing.as_deref(),
        Some(account_number),
        "log in to Mullvad",
    )
}

fn confirm_account_overwrite(
    force: bool,
    existing_account_id: Option<&str>,
    requested_account_id: Option<&str>,
    action: &str,
) -> anyhow::Result<()> {
    if force {
        return Ok(());
    }

    let Some(existing_account_id) = existing_account_id else {
        return Ok(());
    };

    eprintln!("Warning: a saved Mullvad account ID already exists: {existing_account_id}");
    if let Some(requested_account_id) = requested_account_id {
        eprintln!("Requested account ID: {requested_account_id}");
    }
    eprintln!("You are about to {action}, which may replace the saved account ID.");
    eprint!("Continue? [y/N]: ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let answer = input.trim().to_ascii_lowercase();
    if answer == "y" || answer == "yes" {
        return Ok(());
    }

    anyhow::bail!("Aborted by user")
}
