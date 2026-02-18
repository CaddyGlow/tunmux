mod airvpn;
mod api;
mod cli;
mod config;
mod crypto;
mod error;
mod models;
mod proton;
mod wireguard;

use clap::Parser;
use tracing::error;

use cli::{Cli, ProviderCommand};

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

    if let Err(e) = run(cli.provider).await {
        error!("{}", e);
        std::process::exit(1);
    }
}

async fn run(provider: ProviderCommand) -> anyhow::Result<()> {
    match provider {
        ProviderCommand::Proton { command } => proton::handlers::dispatch(command).await,
        ProviderCommand::Airvpn { command } => airvpn::handlers::dispatch(command).await,
    }
}
