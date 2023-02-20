use crate::sign;
use crate::utils::{
    display_string_discreetly, get_derivation_path, load_wallet, user_fuel_wallets_accounts_dir,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use eth_keystore::EthKeystore;
use fuel_crypto::SecretKey;
use fuels::prelude::WalletUnlocked;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Args)]
pub(crate) struct Accounts {
    #[clap(flatten)]
    unverified: Unverified,
}

#[derive(Debug, Args)]
pub(crate) struct Account {
    /// The index of the account.
    ///
    /// This index is used directly within the path used to derive the account.
    index: Option<usize>,
    #[clap(flatten)]
    unverified: Unverified,
    #[clap(subcommand)]
    cmd: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Derive and reveal a new account for the wallet.
    ///
    /// Note that upon derivation of the new account, the account's public
    /// address will be cached in plain text for convenient retrieval via the
    /// `accounts` and `account <ix>` commands.
    ///
    /// The index of the newly derived account will be that which succeeds the
    /// greatest known account index currently within the cache.
    New,
    /// Sign a transaction with the specified account.
    #[clap(subcommand)]
    Sign(sign::Command),
    /// Temporarily display the private key of an account from its index.
    ///
    /// WARNING: This prints your account's private key to an alternative,
    /// temporary, terminal window!
    PrivateKey,
}

#[derive(Debug, Args)]
struct Unverified {
    /// When enabled, shows account addresses stored in the cache without re-deriving them.
    ///
    /// The cache can be found at `~/.fuel/wallets/addresses`.
    ///
    /// Useful for non-interactive scripts on trusted systems or integration tests.
    #[clap(long = "unverified")]
    unverified: bool,
}

pub(crate) fn cli(wallet_path: &Path, account: Account) -> Result<()> {
    match (account.index, account.cmd) {
        (None, Some(Command::New)) => new_cli(wallet_path)?,
        (Some(acc_ix), Some(Command::New)) => new_at_index_cli(wallet_path, acc_ix)?,
        (Some(acc_ix), None) => print_address(wallet_path, acc_ix, account.unverified.unverified)?,
        (Some(acc_ix), Some(Command::Sign(sign_cmd))) => sign::cli(wallet_path, acc_ix, sign_cmd)?,
        (Some(acc_ix), Some(Command::PrivateKey)) => private_key_cli(wallet_path, acc_ix)?,
        (None, Some(cmd)) => print_subcmd_index_warning(&cmd),
        (None, None) => print_subcmd_help(),
    }
    Ok(())
}

/// Prints a list of all known (cached) accounts for the wallet at the given path.
pub(crate) fn print_accounts_cli(wallet_path: &Path, accounts: Accounts) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;
    let addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
    if accounts.unverified.unverified {
        println!("Account addresses (unverified, printed from cache):");
        addresses
            .iter()
            .for_each(|(ix, addr)| println!("[{ix}] {addr}"));
    } else {
        let prompt = "Please enter your password to verify cached accounts: ";
        let password = rpassword::prompt_password(prompt)?;
        for &ix in addresses.keys() {
            let account = derive_new(wallet_path, ix, &password)?;
            let account_addr = account.address().to_string();
            println!("[{ix}] {account_addr}");
            cache_address(&wallet.crypto.ciphertext, ix, &account_addr)?;
        }
    }
    Ok(())
}

fn print_subcmd_help() {
    // The user must provide either the account index or a `New`
    // command - otherwise we print the help output for the
    // `account` subcommand. There doesn't seem to be a nice way
    // of doing this with clap's derive API, so we do-so with a
    // child process.
    std::process::Command::new("forc-wallet")
        .args(["account", "--help"])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output()
        .expect("failed to invoke `forc wallet account --help` command");
}

fn print_subcmd_index_warning(cmd: &Command) {
    let cmd_str = match cmd {
        Command::Sign(_) => "sign",
        Command::PrivateKey => "private-key",
        Command::New => unreachable!("new is valid without an index"),
    };
    eprintln!(
        "Error: The command `{cmd_str}` requires an account index. \
        For example: `forc wallet account <INDEX> {cmd_str} ...`\n"
    );
    print_subcmd_help();
}

/// Print the address of the wallet's account at the given index.
fn print_address(wallet_path: &Path, account_ix: usize, unverified: bool) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;
    if unverified {
        let addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
        match addresses.get(&account_ix) {
            Some(address) => println!("Account {account_ix} address (unverified): {address}"),
            None => eprintln!("Account {account_ix} is not derived yet!"),
        }
    } else {
        let prompt = format!("Please enter your password to verify account {account_ix}: ");
        let password = rpassword::prompt_password(prompt)?;
        let account = derive_new(wallet_path, account_ix, &password)?;
        let account_addr = account.address().to_string();
        println!("Account {account_ix} address: {account_addr}");
        cache_address(&wallet.crypto.ciphertext, account_ix, &account_addr)?;
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

fn new_at_index_cli(wallet_path: &Path, account_ix: usize) -> Result<()> {
    let keystore = load_wallet(wallet_path)?;
    new_at_index(&keystore, wallet_path, account_ix)?;
    Ok(())
}

fn new_cli(wallet_path: &Path) -> Result<()> {
    let keystore = load_wallet(wallet_path)?;
    let addresses = read_cached_addresses(&keystore.crypto.ciphertext)?;
    let account_ix = next_derivation_index(&addresses);
    new_at_index(&keystore, wallet_path, account_ix)?;
    Ok(())
}

pub(crate) fn private_key_cli(wallet_path: &Path, account_ix: usize) -> Result<()> {
    let prompt =
        format!("Please enter your password to display account {account_ix}'s private key: ");
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
    use crate::utils::test_utils::{with_tmp_dir_and_wallet, TEST_PASSWORD};

    #[test]
    fn create_new_account() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            account::derive_new(wallet_path, 0, TEST_PASSWORD).unwrap();
        });
    }

    #[test]
    fn derive_account_by_index() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            // derive account with account index 0
            let account_ix = 0;
            let private_key =
                account::derive_secret_key(wallet_path, account_ix, TEST_PASSWORD).unwrap();
            assert_eq!(
                private_key.to_string(),
                "961bf9754dd036dd13b1d543b3c0f74062bc4ac668ea89d38ce8d712c591f5cf"
            )
        });
    }
}
