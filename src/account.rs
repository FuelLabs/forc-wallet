use crate::utils::{create_accounts_file, number_of_derived_accounts, DEFAULT_WALLETS_VAULT_PATH};
use anyhow::{bail, Result};
use fuels::prelude::*;
use fuels::signers::wallet::Wallet;
use std::path::{Path, PathBuf};

/// Returns the next index for account generation
pub(crate) fn get_next_wallet_index(path: &Path) -> Result<usize, Error> {
    let number_of_derived = number_of_derived_accounts(path)?;
    Ok(number_of_derived)
}

pub(crate) fn new_account(path: Option<String>) -> Result<()> {
    let wallet_path = match &path {
        Some(path) => PathBuf::from(path),
        None => home::home_dir().unwrap().join(DEFAULT_WALLETS_VAULT_PATH),
    };
    if !wallet_path.join(".wallet").exists() {
        bail!("Wallet is not initialized, please initialize a wallet before creating an account! To initialize a wallet: \"forc-wallet init\"");
    }
    let account_index = get_next_wallet_index(&wallet_path)?;
    println!("Generating account with index: {}", account_index);
    let derive_path = format!("m/44'/1179993420'/{}'/0/0", account_index);
    let password = rpassword::prompt_password(
        "Please enter your password to decrypt initialized wallet's phrases: ",
    )?;
    let phrase_recovered = eth_keystore::decrypt_key(wallet_path.join(".wallet"), password)?;
    let phrase = String::from_utf8(phrase_recovered)?;
    let wallet = Wallet::new_from_mnemonic_phrase_with_path(&phrase, None, &derive_path)?;

    // Create/update existing .accounts file
    create_accounts_file(&wallet_path, account_index + 1)?;

    println!("Wallet public address: {}", wallet.address());
    Ok(())
}
