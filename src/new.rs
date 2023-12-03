use crate::utils::{
    display_string_discreetly, request_new_password, write_wallet_from_mnemonic_and_password, should_replace_wallet
};
use fuels::prelude::*;
use std::{path::Path, io::stdin};
use clap::Args;

#[derive(Debug, Args)]
pub struct New {
    /// Forces wallet creation, removing any existing wallet file
    #[clap(short, long)]
    force: bool,
}

pub fn new_wallet_cli(wallet_path: &Path, new: New) -> anyhow::Result<()> {
    ensure_no_wallet_exists(wallet_path, new.force, stdin().lock())?;
    let password = request_new_password();
    // Generate a random mnemonic phrase.
    let mnemonic = generate_mnemonic_phrase(&mut rand::thread_rng(), 24)?;
    write_wallet_from_mnemonic_and_password(wallet_path, &mnemonic, &password)?;
    let mnemonic_string = format!("Wallet mnemonic phrase: {mnemonic}\n");
    display_string_discreetly(
        &mnemonic_string,
        "### Do not share or lose this mnemonic phrase! Press any key to complete. ###",
    )?;
    Ok(())
}
