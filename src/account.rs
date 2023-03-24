use crate::sign;
use crate::utils::{
    display_string_discreetly, get_derivation_path, load_wallet, user_fuel_wallets_accounts_dir,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use eth_keystore::EthKeystore;
use fuel_crypto::{PublicKey, SecretKey};
use fuels_types::bech32::Bech32Address;
use std::str::FromStr;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use url::Url;

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
    Sign(sign::Data),
    /// Temporarily display the private key of an account from its index.
    ///
    /// WARNING: This prints your account's private key to an alternative,
    /// temporary, terminal window!
    PrivateKey,
    /// Reveal the public key for the specified account.
    PublicKey,
    // Reveal the plain address for the specified account. 
    PlainAddress,
    /// Print each asset balance associated with the specified account.
    Balance(Balance),
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

#[derive(Debug, Args)]
pub(crate) struct Balance {
    #[clap(long, default_value_t = crate::DEFAULT_URL.parse().unwrap())]
    node_url: Url,
    #[clap(flatten)]
    unverified: Unverified,
}

/// A map from an account's index to its bech32 address.
type AccountAddresses = BTreeMap<usize, Bech32Address>;

pub(crate) async fn cli(wallet_path: &Path, account: Account) -> Result<()> {
    match (account.index, account.cmd) {
        (None, Some(Command::New)) => new_cli(wallet_path)?,
        (Some(acc_ix), Some(Command::New)) => new_at_index_cli(wallet_path, acc_ix)?,
        (Some(acc_ix), None) => print_address(wallet_path, acc_ix, account.unverified.unverified)?,
        (Some(acc_ix), Some(Command::Sign(sign_cmd))) => {
            sign::wallet_account_cli(wallet_path, acc_ix, sign_cmd)?
        }
        (Some(acc_ix), Some(Command::PrivateKey)) => private_key_cli(wallet_path, acc_ix)?,
        (Some(acc_ix), Some(Command::PublicKey)) => public_key_cli(wallet_path, acc_ix)?,
        (Some(acc_ix), Some(Command::PlainAddress)) => plain_address_cli(wallet_path, acc_ix)?,
        (Some(acc_ix), Some(Command::Balance(balance))) => {
            account_balance_cli(wallet_path, acc_ix, &balance).await?
        }
        (None, Some(cmd)) => print_subcmd_index_warning(&cmd),
        (None, None) => print_subcmd_help(),
    }
    Ok(())
}

pub(crate) async fn balance_cli(wallet_path: &Path, balance: &crate::Balance) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;
    let mut addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
    if !balance.account.unverified.unverified {
        let prompt = "Please enter your password to verify accounts: ";
        let password = rpassword::prompt_password(prompt)?;
        for (&ix, addr) in addresses.iter_mut() {
            let account = derive_account(wallet_path, ix, &password)?;
            if verify_address_and_update_cache(ix, &account, addr, &wallet.crypto.ciphertext)? {
                *addr = account.address().clone();
            }
        }
    };
    println!("Connecting to {}", balance.account.node_url);
    let provider = fuels_signers::provider::Provider::connect(&balance.account.node_url).await?;
    println!("Fetching and summing balances of the following accounts:");
    for (ix, addr) in &addresses {
        println!("  {ix:>3}: {addr}");
    }
    let accounts: Vec<_> = addresses
        .values()
        .map(|addr| fuels_signers::Wallet::from_address(addr.clone(), Some(provider.clone())))
        .collect();
    let account_balances =
        futures::future::try_join_all(accounts.iter().map(|acc| acc.get_balances())).await?;

    if balance.accounts {
        for (ix, balance) in addresses.keys().zip(&account_balances) {
            let balance: BTreeMap<_, _> = balance
                .iter()
                .map(|(id, &val)| (id.clone(), u128::from(val)))
                .collect();
            if balance.is_empty() {
                continue;
            }
            println!("\nAccount {ix}:");
            print_balance(&balance);
        }
    }

    let mut total_balance = BTreeMap::default();
    println!("\nTotal:");
    for acc_bal in account_balances {
        for (asset_id, amt) in acc_bal {
            let entry = total_balance.entry(asset_id.clone()).or_insert(0u128);
            *entry = entry.checked_add(u128::from(amt)).ok_or_else(|| {
                anyhow!("Failed to display balance for asset {asset_id}: Value out of range.")
            })?;
        }
    }
    if total_balance.is_empty() {
        print_balance_empty(&balance.account.node_url);
    } else {
        print_balance(&total_balance);
    }
    Ok(())
}

pub(crate) async fn account_balance_cli(
    wallet_path: &Path,
    acc_ix: usize,
    balance: &Balance,
) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;
    let mut cached_addrs = read_cached_addresses(&wallet.crypto.ciphertext)?;
    let cached_addr = cached_addrs
        .remove(&acc_ix)
        .ok_or_else(|| anyhow!("No cached address for account {acc_ix}"))?;
    let mut account = if balance.unverified.unverified {
        fuels_signers::Wallet::from_address(cached_addr.clone(), None)
    } else {
        let prompt = format!("Please enter your password to verify account {acc_ix}: ");
        let password = rpassword::prompt_password(prompt)?;
        let account = derive_account(wallet_path, acc_ix, &password)?;
        verify_address_and_update_cache(acc_ix, &account, &cached_addr, &wallet.crypto.ciphertext)?;
        account
    };
    println!("Connecting to {}", balance.node_url);
    println!("Fetching the balance of the following account:",);
    println!("  {acc_ix:>3}: {}", account.address());
    let provider = fuels_signers::provider::Provider::connect(&balance.node_url).await?;
    account.set_provider(provider);
    let account_balance: BTreeMap<_, _> = account
        .get_balances()
        .await?
        .into_iter()
        .map(|(ix, val)| (ix, u128::from(val)))
        .collect();
    println!("\nAccount {acc_ix}:");
    if account_balance.is_empty() {
        print_balance_empty(&balance.node_url);
    } else {
        print_balance(&account_balance);
    }
    Ok(())
}

/// Display a warning to the user if the expected address differs from the account address.
/// Returns `Ok(true)` if the address matched, `Ok(false)` if it did not, `Err` if we failed to
/// update the cache.
fn verify_address_and_update_cache(
    acc_ix: usize,
    account: &fuels_signers::Wallet,
    expected_addr: &Bech32Address,
    wallet_ciphertext: &[u8],
) -> Result<bool> {
    println!("Verifying account {acc_ix}");
    let addr = account.address();
    if addr == expected_addr {
        return Ok(true);
    }
    println!(
        "WARNING: Cached address for account {acc_ix} differs from derived address.\n  \
          Cached:  {expected_addr}
          Derived: {addr}
        Updating cache with newly derived address.",
    );
    cache_address(wallet_ciphertext, acc_ix, addr)?;
    Ok(false)
}

fn print_balance_empty(node_url: &Url) {
    let beta_2_url = crate::BETA_2_URL.parse::<Url>().unwrap();
    match node_url.host_str() {
        host if host == beta_2_url.host_str() => {
            println!(
                "  Account empty. Visit the faucet to acquire some test funds: {}",
                crate::BETA_2_FAUCET_URL
            )
        }
        _ => println!("Account empty,"),
    }
}

fn print_balance(balance: &BTreeMap<String, u128>) {
    let asset_id_header = "Asset ID";
    let amount_header = "Amount";
    println!("  {asset_id_header:66} {amount_header}");
    for (asset_id, amount) in balance {
        println!("  {asset_id} {amount}");
    }
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
            let account = derive_account(wallet_path, ix, &password)?;
            let account_addr = account.address();
            println!("[{ix}] {account_addr}");
            cache_address(&wallet.crypto.ciphertext, ix, account_addr)?;
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
        Command::PublicKey => "public-key",
        Command::PlainAddress => "plain-address",
        Command::Balance(_) => "balance",
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
        let account = derive_account(wallet_path, account_ix, &password)?;
        let account_addr = account.address();
        println!("Account {account_ix} address: {account_addr}");
        cache_address(&wallet.crypto.ciphertext, account_ix, account_addr)?;
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

fn next_derivation_index(addrs: &AccountAddresses) -> usize {
    addrs.last_key_value().map(|(&ix, _)| ix + 1).unwrap_or(0)
}

/// Derive an account at the first index succeeding the greatest known existing index.
fn derive_account_unlocked(
    wallet_path: &Path,
    account_ix: usize,
    password: &str,
) -> Result<fuels_signers::WalletUnlocked> {
    let secret_key = derive_secret_key(wallet_path, account_ix, password)?;
    let wallet = fuels_signers::WalletUnlocked::new_from_private_key(secret_key, None);
    Ok(wallet)
}

fn derive_account(
    wallet_path: &Path,
    account_ix: usize,
    password: &str,
) -> Result<fuels_signers::Wallet> {
    Ok(derive_account_unlocked(wallet_path, account_ix, password)?.lock())
}

fn new_at_index(
    keystore: &EthKeystore,
    wallet_path: &Path,
    account_ix: usize,
) -> Result<Bech32Address> {
    let prompt = format!("Please enter your password to derive account {account_ix}: ");
    let password = rpassword::prompt_password(prompt)?;
    let account = derive_account(wallet_path, account_ix, &password)?;
    let account_addr = account.address();
    cache_address(&keystore.crypto.ciphertext, account_ix, account_addr)?;
    println!("Wallet address: {account_addr}");
    Ok(account_addr.clone())
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

/// Prints the public key of given account index.
fn public_key_cli(wallet_path: &Path, account_ix: usize) -> Result<()> {
    let prompt =
        format!("Please enter your password to display account {account_ix}'s public key: ");
    let password = rpassword::prompt_password(prompt)?;
    let secret_key = derive_secret_key(wallet_path, account_ix, &password)?;
    let public_key = PublicKey::from(&secret_key);
    println!("Public key for account {account_ix}: {public_key}");
    Ok(())
}

//Prints the plain Address formatted pub key @{account_ix} (the one that doesn't start with 'fuel...')
fn plain_address_cli(wallet_path: &Path, account_ix: usize) -> Result<()> {
    let prompt =
        format!("Please enter your password to display account {account_ix}'s plain address: ");
    let password = rpassword::prompt_password(prompt)?;
    let secret_key = derive_secret_key(wallet_path, account_ix, &password)?;
    let public_key = format!("{}", PublicKey::from(&secret_key));
    let bech = Bech32Address::from_str(&public_key).expect("failed to create Bech32 address from String");
    let plain_address: fuel_types::Address = bech.into();
    println!("Plain address for {}: {}", account_ix, plain_address);
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
fn cache_address(
    wallet_ciphertext: &[u8],
    account_ix: usize,
    account_addr: &Bech32Address,
) -> Result<()> {
    let path = address_path(wallet_ciphertext, account_ix);
    if path.exists() && !path.is_file() {
        bail!("attempting to cache account address to {path:?}, but the path is a directory");
    }
    let parent = path
        .parent()
        .expect("account address path contained no parent directory");
    fs::create_dir_all(parent).context("failed to create account address cache directory")?;
    fs::write(path, account_addr.to_string()).context("failed to cache account address to file")?;
    Ok(())
}

/// Read all cached account addresses for the wallet with the given ciphertext.
fn read_cached_addresses(wallet_ciphertext: &[u8]) -> Result<AccountAddresses> {
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
            let account_addr_str = std::fs::read_to_string(&path)
                .context("failed to read account address from cache")?;
            let account_addr = account_addr_str
                .parse()
                .context("failed to parse cached account address as a bech32 address")?;
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
            account::derive_account(wallet_path, 0, TEST_PASSWORD).unwrap();
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
    #[test]
    fn derive_plain_address(){
        let address = "fuel1j78es08cyyz5n75jugal7p759ccs323etnykzpndsvhzu6399yqqpjmmd2";
        let bech32 =
            <fuels_types::bech32::Bech32Address as std::str::FromStr>::from_str(address).expect("failed to create Bech32 address from string");
        let plain_address: fuel_types::Address = bech32.into();
        assert_eq!(
            <fuel_types::Address as std::str::FromStr>::from_str("978f983cf8210549fa92e23bff07d42e3108aa395cc961066d832e2e6a252900").expect("RIP"),
            plain_address
        )
    }
}
