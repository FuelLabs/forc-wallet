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

    /// Directly provide the wallet password when create new wallet.
    ///
    /// WARNING: This is primarily provided for non-interactive testing. Using this flag is
    /// prone to leaving your password exposed in your shell command history!
    #[clap(short, long)]
    pub password_non_interactive: Option<String>,

    /// Silent mode, do not display the mnemonic phrase.
    #[clap(short, long)]
    pub silent: bool,
}

pub fn new_wallet_cli(wallet_path: &Path, new: New) -> anyhow::Result<()> {
    ensure_no_wallet_exists(wallet_path, new.force, stdin().lock())?;
    let password = new.password_non_interactive.unwrap_or_else(request_new_password);
    // Generate a random mnemonic phrase.
    let mnemonic = generate_mnemonic_phrase(&mut rand::thread_rng(), 24)?;
    write_wallet_from_mnemonic_and_password(wallet_path, &mnemonic, &password)?;

    derive_and_cache_addresses(
        &load_wallet(wallet_path)?,
        &mnemonic,
        0..new.cache_accounts.unwrap_or(DEFAULT_CACHE_ACCOUNTS),
    )?;

    let mnemonic_string = format!("Wallet mnemonic phrase: {mnemonic}\n");

    if !new.silent {
        display_string_discreetly(
            &mnemonic_string,
            "### Do not share or lose this mnemonic phrase! Press any key to complete. ###",
        )?;
    }
    Ok(())
}
