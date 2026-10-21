use std::fs;

use anyhow::Context;

use crate::cli::WgconfCommand;
use tunmux_core::config::AppConfig;
use tunmux_core::wgconf::handlers::{
    connect, disconnect, list_profiles, remove_profile, save_profile_content,
};

pub async fn dispatch(command: WgconfCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        WgconfCommand::Connect(args) => connect(args.into(), config),
        WgconfCommand::Disconnect { instance, all } => disconnect(instance, all, config),
        WgconfCommand::Save { file, name } => cmd_save(&file, &name),
        WgconfCommand::List => cmd_list(),
        WgconfCommand::Remove { name } => cmd_remove(&name),
    }
}

fn cmd_save(file: &str, name: &str) -> anyhow::Result<()> {
    let text = fs::read_to_string(file).with_context(|| format!("failed to read {}", file))?;
    save_profile_content(name, &text)?;
    println!("Saved profile {} from {}", name, file);
    Ok(())
}

fn cmd_list() -> anyhow::Result<()> {
    let profiles = list_profiles()?;
    if profiles.is_empty() {
        println!("No saved wgconf profiles.");
        return Ok(());
    }

    for name in profiles {
        println!("{}", name);
    }
    Ok(())
}

fn cmd_remove(name: &str) -> anyhow::Result<()> {
    remove_profile(name)?;
    println!("Removed profile {}", name);
    Ok(())
}
