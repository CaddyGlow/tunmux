use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "protonvpn", about = "Proton VPN CLI (Rust)", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Sign in with Proton VPN credentials
    Login {
        /// Proton account username
        username: String,
    },

    /// Sign out and remove credentials
    Logout,

    /// Display account information
    Info,

    /// List available VPN servers
    Servers {
        /// Filter by country code (e.g., US, CH, JP)
        #[arg(short, long)]
        country: Option<String>,

        /// Show only free servers
        #[arg(short, long)]
        free: bool,
    },

    /// Connect to a VPN server
    Connect {
        /// Server name (e.g., US#1, CH#5)
        server: Option<String>,

        /// Connect to a server in this country
        #[arg(short, long)]
        country: Option<String>,

        /// Prefer P2P-capable servers
        #[arg(long)]
        p2p: bool,
    },

    /// Disconnect from VPN
    Disconnect,
}
