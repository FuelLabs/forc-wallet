use crate::utils::{
    display_string_discreetly, get_derivation_path, load_wallet, user_fuel_wallets_accounts_dir,
};
use anyhow::{anyhow, bail, Context, Result};
use eth_keystore::EthKeystore;
use fuel_crypto::SecretKey;
use fuels::prelude::WalletUnlocked;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Prints a list of all known (cached) accounts for the wallet at the given path.
pub(crate) fn print_address_list(wallet_path: &Path) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;
    let addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
    for (ix, addr) in addresses {
        println!("[{ix}] {addr}");
    }
    Ok(())
}

/// Print the address of the wallet's account at the given index.
pub(crate) fn print_address(wallet_path: &Path, account_ix: usize) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;
    let addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
    match addresses.get(&account_ix) {
        Some(address) => println!("Account {account_ix} address: {address}"),
        None => eprintln!("Account {account_ix} is not derived yet!"),
    }
    Ok(())
}

/// Given a path to a wallet, an account index and the wallet's password,
/// derive the account address for the account at the given index.
pub(crate) fn derive_secret_key(
    wallet_path: &Path,
    account_index: usize,
    password: &str,
) -> Result<SecretKey> {
    let phrase_recovered = eth_keystore::decrypt_key(wallet_path, password)?;
    let phrase = String::from_utf8(phrase_recovered)?;
    let derive_path = get_derivation_path(account_index);
    let secret_key = SecretKey::new_from_mnemonic_phrase_with_path(&phrase, &derive_path)?;
    Ok(secret_key)
}

fn next_derivation_index(addrs: &BTreeMap<usize, String>) -> usize {
    addrs.last_key_value().map(|(&ix, _)| ix + 1).unwrap_or(0)
}

/// Derive an account at the first index succeeding the greatest known existing index.
fn derive_new(wallet_path: &Path, account_ix: usize, password: &str) -> Result<WalletUnlocked> {
    let secret_key = derive_secret_key(wallet_path, account_ix, password)?;
    let wallet = WalletUnlocked::new_from_private_key(secret_key, None);
    Ok(wallet)
}

fn new_at_index(keystore: &EthKeystore, wallet_path: &Path, account_ix: usize) -> Result<String> {
    let prompt = format!("Please enter your password to derive account {account_ix}: ");
    let password = rpassword::prompt_password(prompt)?;
    let wallet_unlocked = derive_new(wallet_path, account_ix, &password)?;
    let account_addr = wallet_unlocked.address().to_string();
    cache_address(&keystore.crypto.ciphertext, account_ix, &account_addr)?;
    println!("Wallet address: {account_addr}");
    Ok(account_addr)
}

pub(crate) fn new_at_index_cli(wallet_path: &Path, account_ix: usize) -> Result<()> {
    let keystore = load_wallet(wallet_path)?;
    new_at_index(&keystore, wallet_path, account_ix)?;
    Ok(())
}

pub(crate) fn new_cli(wallet_path: &Path) -> Result<()> {
    let keystore = load_wallet(wallet_path)?;
    let addresses = read_cached_addresses(&keystore.crypto.ciphertext)?;
    let account_ix = next_derivation_index(&addresses);
    new_at_index(&keystore, wallet_path, account_ix)?;
    Ok(())
}

pub(crate) fn export_cli(wallet_path: &Path, account_ix: usize) -> Result<()> {
    let prompt =
        format!("Please enter your password to export account {account_ix}'s private key: ");
    let password = rpassword::prompt_password(prompt)?;
    let secret_key = derive_secret_key(wallet_path, account_ix, &password)?;
    let secret_key_string = format!("Secret key for account {account_ix}: {secret_key}\n");
    display_string_discreetly(&secret_key_string, "### Press any key to complete. ###")?;
    Ok(())
}

/// A unique 64-bit hash is created from the wallet's ciphertext to use as a unique directory name.
fn address_cache_dir_name(wallet_ciphertext: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let hasher = &mut std::collections::hash_map::DefaultHasher::default();
    wallet_ciphertext.iter().for_each(|byte| byte.hash(hasher));
    let hash = hasher.finish();
    format!("{hash:x}")
}

/// The path in which a wallet's account addresses will be cached.
fn address_cache_dir(wallet_ciphertext: &[u8]) -> PathBuf {
    user_fuel_wallets_accounts_dir().join(address_cache_dir_name(wallet_ciphertext))
}

/// The cache path for a wallet account address.
fn address_path(wallet_ciphertext: &[u8], account_ix: usize) -> PathBuf {
    address_cache_dir(wallet_ciphertext).join(format!("{account_ix}"))
}

/// Cache a single wallet account address to a file as a simple utf8 string.
fn cache_address(wallet_ciphertext: &[u8], account_ix: usize, account_addr: &str) -> Result<()> {
    let path = address_path(wallet_ciphertext, account_ix);
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
fn read_cached_addresses(wallet_ciphertext: &[u8]) -> Result<BTreeMap<usize, String>> {
    let wallet_accounts_dir = address_cache_dir(wallet_ciphertext);
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
    use crate::account;
    use crate::utils::test_utils::{save_dummy_wallet_file, with_tmp_folder, TEST_PASSWORD};

    #[test]
    fn create_new_account() {
        with_tmp_folder(|tmp_folder| {
            // init test wallet
            let wallet_path = tmp_folder.join("wallet.json");
            save_dummy_wallet_file(&wallet_path);
            account::derive_new(&wallet_path, 0, TEST_PASSWORD).unwrap();
        });
    }

    #[test]
    fn derive_account_by_index() {
        with_tmp_folder(|tmp_folder| {
            // initialize a wallet
            let wallet_path = tmp_folder.join("wallet.json");
            save_dummy_wallet_file(&wallet_path);
            // derive account with account index 0
            let account_ix = 0;
            let private_key =
                account::derive_secret_key(&wallet_path, account_ix, TEST_PASSWORD).unwrap();
            assert_eq!(
                private_key.to_string(),
                "961bf9754dd036dd13b1d543b3c0f74062bc4ac668ea89d38ce8d712c591f5cf"
            )
        });
    }
}
