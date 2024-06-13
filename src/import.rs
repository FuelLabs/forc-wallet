use crate::{
    account::derive_and_cache_addresses,
    utils::{
        ensure_no_wallet_exists, load_wallet, request_new_password,
        write_wallet_from_mnemonic_and_password,
    },
    DEFAULT_CACHE_ACCOUNTS,
};
use anyhow::{bail, Result};
use clap::Args;
use fuels::accounts::wallet::WalletUnlocked;
use std::{io::stdin, path::Path};

#[derive(Debug, Args)]
pub struct Import {
    /// Forces wallet creation, removing any existing wallet file
    #[clap(short, long)]
    force: bool,
    /// How many accounts to cache by default (Default 10)
    #[clap(short, long)]
    pub cache_accounts: Option<usize>,
}

/// Check if given mnemonic is valid by trying to create a `WalletUnlocked` from it
fn check_mnemonic(mnemonic: &str) -> Result<()> {
    // Check users's phrase by trying to create a wallet from it
    if WalletUnlocked::new_from_mnemonic_phrase(mnemonic, None).is_err() {
        bail!("Cannot generate a wallet from provided mnemonics, please check your mnemonic phrase")
    }
    Ok(())
}

pub fn import_wallet_cli(wallet_path: &Path, import: Import) -> Result<()> {
    ensure_no_wallet_exists(wallet_path, import.force, stdin().lock())?;

    let mnemonic = rpassword::prompt_password("Please enter your mnemonic phrase: ")?;
    check_mnemonic(&mnemonic)?;
    let password = request_new_password();
    write_wallet_from_mnemonic_and_password(wallet_path, &mnemonic, &password)?;
    derive_and_cache_addresses(
        &load_wallet(wallet_path)?,
        &mnemonic,
        0..import.cache_accounts.unwrap_or(DEFAULT_CACHE_ACCOUNTS),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::TEST_MNEMONIC;

    #[test]
    fn check_mnemonic_should_succeed() {
        assert!(check_mnemonic(TEST_MNEMONIC).is_ok())
    }

    #[test]
    fn check_mnemonic_should_fail() {
        let invalid_mnemonic = "this is an invalid mnemonic";
        assert!(check_mnemonic(invalid_mnemonic).is_err())
    }
}
