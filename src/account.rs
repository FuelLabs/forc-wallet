use crate::list::get_wallets_list;
use anyhow::{bail, Result};
use fuels::prelude::*;
use fuels::signers::wallet::Wallet;
use std::path::PathBuf;

pub(crate) const DEFAULT_WALLETS_VAULT_PATH: &str = ".fuel/wallets/";

/// Walks through the wallets vault directory and returns the next index based on the number of
/// wallets in the vault.
pub(crate) fn get_next_wallet_index(dir: &str) -> Result<usize, Error> {
    let sorted_wallets = get_wallets_list(dir)?;
    if let Some(last) = sorted_wallets.last() {
        Ok(last.0 + 1)
    } else {
        Ok(0)
    }
}

pub(crate) fn new_account(path: Option<String>) -> Result<()> {
    let wallet_path = match &path {
        Some(path) => PathBuf::from(path),
        None => home::home_dir().unwrap().join(DEFAULT_WALLETS_VAULT_PATH),
    };
    if !wallet_path.join(".wallet").exists() {
        bail!("Wallet is not initialized, please initialize a wallet before creating an account! To initialize a wallet: \"forc-wallet init\"");
    }
    let account_index =
        get_next_wallet_index(&path.unwrap_or_else(|| DEFAULT_WALLETS_VAULT_PATH.to_string()))?;
    println!("Generating account with index: {}", account_index);
    let derive_path = format!("m/44'/1179993420'/{}'/0/0", account_index);
    let password = rpassword::prompt_password(
        "Please enter your password to decrypt initialized wallet's phrases: ",
    )?;
    let phrase_recovered = eth_keystore::decrypt_key(wallet_path.join(".wallet"), password)?;
    let phrase = String::from_utf8(phrase_recovered)?;
    let wallet = Wallet::new_from_mnemonic_phrase_with_path(&phrase, None, &derive_path)?;

    let password = rpassword::prompt_password(
        "Account generated, please enter a password to encrypt the private key: ",
    )
    .unwrap();

    let confirmation = rpassword::prompt_password("Please confirm your password: ").unwrap();

    if password != confirmation {
        bail!("Passwords do not match -- try again!");
    }

    // TODO: check that the path has the right index??? not rly sure
    // Wallets are created in ~/.fuel/wallets/ or the given path following the format below:
    // <index>_<public_address>/<uuid>.
    // The index is the wallet's index in the list of wallets.
    let wallet_path = wallet_path.join(format!(
        "{}_{}",
        get_next_wallet_index(DEFAULT_WALLETS_VAULT_PATH).unwrap(),
        wallet.address()
    ));

    // create directory if it doesn't exist.
    if !wallet_path.exists() {
        std::fs::create_dir_all(&wallet_path).unwrap();
    }

    // Encrypt the wallet and store it in the vault.
    let uuid = wallet.encrypt(wallet_path, password).unwrap();

    println!("\nJSON Wallet uuid: {}", uuid);
    println!("Wallet public address: {}", wallet.address());

    Ok(())
}
