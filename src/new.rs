use crate::{
    account::derive_and_cache_addresses,
    utils::{
        display_string_discreetly, ensure_no_wallet_exists, load_wallet, request_new_password,
        write_wallet_from_mnemonic_and_password,
    },
    DEFAULT_CACHE_ACCOUNTS,
};
use clap::Args;
use fuels::prelude::*;
use std::{io::stdin, path::Path};

#[derive(Debug, Args)]
pub struct New {
    /// Forces wallet creation, removing any existing wallet file
    #[clap(short, long)]
    pub force: bool,

    /// How many accounts to cache by default (Default 10)
    #[clap(short, long)]
    pub cache_accounts: Option<usize>,
}

pub fn new_wallet_cli(wallet_path: &Path, new: New) -> anyhow::Result<()> {
    ensure_no_wallet_exists(wallet_path, new.force, stdin().lock())?;
    let password = request_new_password();
    // Generate a random mnemonic phrase.
    let mnemonic = new_wallet(
        wallet_path,
        &password,
        new.cache_accounts.unwrap_or(DEFAULT_CACHE_ACCOUNTS),
    )?;

    let mnemonic_string = format!("Wallet mnemonic phrase: {mnemonic}\n");
    display_string_discreetly(
        &mnemonic_string,
        "### Do not share or lose this mnemonic phrase! Press any key to complete. ###",
    )?;
    Ok(())
}

pub fn new_wallet(
    wallet_path: &Path,
    password: &str,
    cache_count: usize,
) -> anyhow::Result<String> {
    let mnemonic = generate_mnemonic_phrase(&mut rand::thread_rng(), 24)?;
    write_wallet_from_mnemonic_and_password(wallet_path, &mnemonic, &password)?;
    derive_and_cache_addresses(&load_wallet(wallet_path)?, &mnemonic, 0..cache_count)?;
    Ok(mnemonic)
}
