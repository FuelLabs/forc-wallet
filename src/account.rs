use crate::utils::{
    default_wallet_path, get_derivation_path, load_wallet, user_fuel_wallets_accounts_dir,
};
use anyhow::{anyhow, bail, Context, Result};
use fuels::prelude::WalletUnlocked;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Prints a list of all known accounts for the wallet at the given path.
pub(crate) fn print_account_list(path_opt: Option<PathBuf>) -> Result<()> {
    let wallet_path = path_opt.unwrap_or_else(default_wallet_path);
    let wallet = load_wallet(&wallet_path)?;
    let addresses = read_cached_account_addresses(&wallet.crypto.ciphertext)?;
    for (ix, addr) in addresses {
        println!("[{ix}] {addr}");
    }
    Ok(())
}

pub(crate) fn print_account_address(path_opt: Option<PathBuf>, account_ix: usize) -> Result<()> {
    let wallet_path = path_opt.unwrap_or_else(default_wallet_path);
    let wallet = load_wallet(&wallet_path)?;
    let addresses = read_cached_account_addresses(&wallet.crypto.ciphertext)?;
    if let Some(address) = addresses.get(&account_ix) {
        println!("Account {account_ix} address: {address}");
    } else {
        eprintln!("Account {account_ix} is not derived yet!");
    }
    Ok(())
}

fn new_account(wallet_path: &Path, password: &str) -> Result<WalletUnlocked> {
    let wallet = load_wallet(wallet_path)?;
    let addresses = read_cached_account_addresses(&wallet.crypto.ciphertext)?;
    let account_index = addresses.len();
    println!("Generating account with index: {account_index}");
    let derive_path = get_derivation_path(account_index);
    let phrase_recovered = eth_keystore::decrypt_key(wallet_path, password)?;
    let phrase = String::from_utf8(phrase_recovered)?;
    let wallet = WalletUnlocked::new_from_mnemonic_phrase_with_path(&phrase, None, &derive_path)?;
    Ok(wallet)
}

pub(crate) fn new_account_cli(path_opt: Option<PathBuf>) -> Result<()> {
    let wallet_path = path_opt.unwrap_or_else(default_wallet_path);
    let wallet = load_wallet(&wallet_path).map_err(|e| {
        anyhow!(
            "Failed to load a wallet from {wallet_path:?}: {e}.\n\
                Please be sure to initialize a wallet before creating an account.\n\
                To initialize a wallet, use `forc-wallet init`"
        )
    })?;
    let password = rpassword::prompt_password(
        "Please enter your password to decrypt initialized wallet's phrases: ",
    )?;
    let addresses = read_cached_account_addresses(&wallet.crypto.ciphertext)?;
    let account_ix = addresses.last_key_value().map(|(&ix, _)| ix).unwrap_or(0);
    let wallet_unlocked = new_account(&wallet_path, &password)?;
    let account_addr = wallet_unlocked.address().to_string();
    cache_account_address(&wallet.crypto.ciphertext, account_ix, &account_addr)?;
    println!("Wallet address: {account_addr}");
    Ok(())
}

/// A unique 64-bit hash is created from the wallet's ciphertext to use as a unique directory name.
fn wallet_account_address_cache_dir_name(wallet_ciphertext: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let hasher = &mut std::collections::hash_map::DefaultHasher::default();
    wallet_ciphertext.iter().for_each(|byte| byte.hash(hasher));
    let hash = hasher.finish();
    format!("{hash:x}")
}

/// The path in which a wallet's account addresses will be cached.
fn wallet_account_address_cache_dir(wallet_ciphertext: &[u8]) -> PathBuf {
    user_fuel_wallets_accounts_dir().join(wallet_account_address_cache_dir_name(wallet_ciphertext))
}

/// The cache path for a wallet account address.
fn account_address_path(wallet_ciphertext: &[u8], account_ix: usize) -> PathBuf {
    wallet_account_address_cache_dir(wallet_ciphertext).join(format!("{account_ix}"))
}

/// Cache a single wallet account address to a file as a simple utf8 string.
fn cache_account_address(
    wallet_ciphertext: &[u8],
    account_ix: usize,
    account_addr: &str,
) -> Result<()> {
    let path = account_address_path(wallet_ciphertext, account_ix);
    if path.exists() {
        if !path.is_file() {
            bail!("attempting to cache account address to {path:?}, but the path is a directory");
        }
        return Ok(());
    }
    let parent = path
        .parent()
        .expect("account address path contained no parent directory");
    fs::create_dir_all(parent).context("failed to create account address cache directory")?;
    fs::write(path, account_addr).context("failed to cache account address to file")?;
    Ok(())
}

/// Read all cached account addresses for the wallet with the given ciphertext.
fn read_cached_account_addresses(wallet_ciphertext: &[u8]) -> Result<BTreeMap<usize, String>> {
    let wallet_accounts_dir = wallet_account_address_cache_dir(wallet_ciphertext);
    if !wallet_accounts_dir.exists() {
        return Ok(Default::default());
    }
    fs::read_dir(&wallet_accounts_dir)
        .context("failed to read account address cache")?
        .map(|res| {
            let entry = res.context("failed to read account address cache")?;
            let path = entry.path();
            let file_name = path
                .file_name()
                .and_then(|os_str| os_str.to_str())
                .ok_or_else(|| anyhow!("failed to read utf8 file name from {path:?}"))?;
            let account_ix: usize = file_name
                .parse()
                .context("failed to parse account index from file name")?;
            let account_addr = std::fs::read_to_string(&path)
                .context("failed to read account address from cache")?;
            Ok((account_ix, account_addr))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{save_dummy_wallet_file, with_tmp_folder, TEST_PASSWORD};

    #[test]
    fn create_new_account() {
        with_tmp_folder(|tmp_folder| {
            // init test wallet
            let wallet_path = tmp_folder.join("wallet.json");
            save_dummy_wallet_file(&wallet_path);
            new_account(&wallet_path, TEST_PASSWORD).unwrap();
        });
    }
}
