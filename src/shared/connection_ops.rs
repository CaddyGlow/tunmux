use crate::wireguard::backend::WgBackend;
use crate::wireguard::connection::ConnectionState;

pub fn resolve_connect_backend(
    backend_arg: Option<&str>,
    default_backend: &str,
    use_proxy: bool,
    use_local_proxy: bool,
) -> anyhow::Result<WgBackend> {
    let backend_str = backend_arg.unwrap_or(default_backend);

    if use_proxy && use_local_proxy {
        anyhow::bail!("--proxy and --local-proxy are mutually exclusive");
    }

    #[cfg(not(target_os = "linux"))]
    if use_proxy {
        anyhow::bail!("--proxy is available only on Linux");
    }

    if use_proxy && matches!(backend_str, "wg-quick" | "userspace") {
        anyhow::bail!(
            "--proxy requires kernel backend (incompatible with --backend {})",
            backend_str
        );
    }

    if use_proxy {
        Ok(WgBackend::Kernel)
    } else {
        WgBackend::from_str_arg(backend_str)
    }
}

pub fn validate_disable_ipv6_direct_kernel(
    disable_ipv6: bool,
    use_proxy: bool,
    use_local_proxy: bool,
    backend: WgBackend,
) -> anyhow::Result<()> {
    if disable_ipv6 && (use_proxy || use_local_proxy || backend != WgBackend::Kernel) {
        anyhow::bail!(
            "--disable-ipv6 is supported only for direct kernel mode (no --proxy/--local-proxy)"
        );
    }

    Ok(())
}

pub fn disconnect_provider_connections<F>(
    provider_name: &str,
    instance: Option<String>,
    all: bool,
    mut disconnect_one: F,
) -> anyhow::Result<()>
where
    F: FnMut(&ConnectionState) -> anyhow::Result<()>,
{
    if all {
        let connections = ConnectionState::load_all()?;
        let mine: Vec<_> = connections
            .into_iter()
            .filter(|c| c.provider == provider_name)
            .collect();
        if mine.is_empty() {
            println!("No active {} connections.", provider_name);
            return Ok(());
        }
        for conn in mine {
            disconnect_one(&conn)?;
            println!("Disconnected {}", conn.instance_name);
        }
        return Ok(());
    }

    if let Some(ref name) = instance {
        let conn = ConnectionState::load(name)?
            .ok_or_else(|| anyhow::anyhow!("no connection with instance {:?}", name))?;
        if conn.provider != provider_name {
            anyhow::bail!(
                "instance {:?} belongs to provider {:?}, not {}",
                name,
                conn.provider,
                provider_name
            );
        }
        disconnect_one(&conn)?;
        println!("Disconnected {}", name);
        return Ok(());
    }

    let connections = ConnectionState::load_all()?;
    let mine: Vec<_> = connections
        .into_iter()
        .filter(|c| c.provider == provider_name)
        .collect();

    match mine.len() {
        0 => {
            println!("Not connected.");
        }
        1 => {
            let conn = &mine[0];
            disconnect_one(conn)?;
            println!("Disconnected {}", conn.instance_name);
        }
        _ => {
            println!("Multiple active connections. Specify which to disconnect:\n");
            for conn in &mine {
                let ports = match (conn.socks_port, conn.http_port) {
                    (Some(s), Some(h)) => format!("SOCKS5 :{}, HTTP :{}", s, h),
                    _ => "-".to_string(),
                };
                println!(
                    "  {}  {}  {}",
                    conn.instance_name, conn.server_display_name, ports
                );
            }
            println!("\nUsage: tunmux disconnect <instance>");
            println!(
                "       tunmux disconnect --provider {} --all",
                provider_name
            );
        }
    }

    Ok(())
}
