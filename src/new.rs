use crate::{
    account::derive_and_cache_addresses,
    utils::{
        display_string_discreetly, ensure_no_wallet_exists, request_new_password,
        write_wallet_from_mnemonic_and_password,
    },
    DEFAULT_CACHE_ACCOUNTS,
};
use clap::Args;
use fuels::accounts::signers::private_key::generate_mnemonic_phrase;
use std::io::stdin;

#[derive(Debug, Args)]
pub struct New {
    /// Forces wallet creation, removing any existing wallet file
    #[clap(short, long)]
    pub force: bool,

    /// How many accounts to cache by default (Default 10)
    #[clap(short, long)]
    pub cache_accounts: Option<usize>,
}

pub async fn new_wallet_cli(ctx: &crate::CliContext, new: New) -> anyhow::Result<()> {
    ensure_no_wallet_exists(&ctx.wallet_path, new.force, stdin().lock())?;
    let password = request_new_password();
    // Generate a random mnemonic phrase.
    let mnemonic = generate_mnemonic_phrase(&mut rand::thread_rng(), 24)?;
    write_wallet_from_mnemonic_and_password(&ctx.wallet_path, &mnemonic, &password)?;

    derive_and_cache_addresses(
        ctx,
        &mnemonic,
        0..new.cache_accounts.unwrap_or(DEFAULT_CACHE_ACCOUNTS),
    )
    .await?;

    let mnemonic_string = format!("Wallet mnemonic phrase: {mnemonic}\n");
    display_string_discreetly(
        &mnemonic_string,
        "### Do not share or lose this mnemonic phrase! Press any key to complete. ###",
    )?;
    Ok(())
}
