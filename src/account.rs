use crate::format::Table;
use crate::sign;
use crate::utils::{
    display_string_discreetly, get_derivation_path, load_wallet, user_fuel_wallets_accounts_dir,
};
use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use eth_keystore::EthKeystore;
use forc_tracing::println_warning;
use fuels::accounts::ViewOnlyAccount;
use fuels::accounts::provider::Provider;
use fuels::accounts::signers::private_key::PrivateKeySigner;
use fuels::accounts::wallet::{Unlocked, Wallet};
use fuels::crypto::{PublicKey, SecretKey};
use fuels::types::checksum_address::checksum_encode;
use fuels::types::transaction::TxPolicies;
use fuels::types::{Address, AssetId};
use std::ops::Range;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use url::Url;

type WalletUnlocked<S> = Wallet<Unlocked<S>>;

#[derive(Debug, Args)]
pub struct Accounts {
    #[clap(flatten)]
    unverified: UnverifiedOpt,
}

#[derive(Debug, Args)]
pub struct Account {
    /// The index of the account.
    ///
    /// This index is used directly within the path used to derive the account.
    index: Option<usize>,
    #[clap(flatten)]
    unverified: UnverifiedOpt,
    #[clap(subcommand)]
    cmd: Option<Command>,
}

#[derive(Debug, Args)]
pub(crate) struct Fmt {
    /// Option for public key to be displayed as hex / bytes.
    ///
    /// pass in --as-hex for this alternative display.
    #[clap(long)]
    as_hex: bool,
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
    /// Takes an optional bool flag --as-hex that displays the PublicKey in hex format.
    PublicKey(Fmt),
    /// Print each asset balance associated with the specified account.
    Balance(Balance),
    /// Transfer assets from this account to another.
    Transfer(Transfer),
}

#[derive(Debug, Args)]
pub(crate) struct Balance {
    #[clap(flatten)]
    pub(crate) unverified: UnverifiedOpt,
}

#[derive(Debug, Args)]
pub(crate) struct Transfer {
    /// The address of the account to transfer assets to.
    #[clap(long)]
    to: Address,
    /// Amount (in u64) of assets to transfer.
    #[clap(long)]
    amount: u64,
    /// Asset ID of the asset to transfer.
    #[clap(long)]
    asset_id: AssetId,
    #[clap(long)]
    gas_price: Option<u64>,
    #[clap(long)]
    gas_limit: Option<u64>,
    #[clap(long)]
    maturity: Option<u64>,
}

#[derive(Debug, Args)]
pub(crate) struct UnverifiedOpt {
    /// When enabled, shows account addresses stored in the cache without re-deriving them.
    ///
    /// The cache can be found at `~/.fuel/wallets/addresses`.
    ///
    /// Useful for non-interactive scripts on trusted systems or integration tests.
    #[clap(long = "unverified")]
    pub(crate) unverified: bool,
}

/// A map from an account's index to its address.
type AccountAddresses = BTreeMap<usize, Address>;

pub async fn cli(ctx: &crate::CliContext, account: Account) -> Result<()> {
    match (account.index, account.cmd) {
        (None, Some(Command::New)) => new_cli(ctx).await?,
        (Some(acc_ix), Some(Command::New)) => new_at_index_cli(ctx, acc_ix).await?,
        (Some(acc_ix), None) => print_address(ctx, acc_ix, account.unverified.unverified).await?,
        (Some(acc_ix), Some(Command::Sign(sign_cmd))) => {
            sign::wallet_account_cli(ctx, acc_ix, sign_cmd)?
        }
        (Some(acc_ix), Some(Command::PrivateKey)) => private_key_cli(ctx, acc_ix)?,
        (Some(acc_ix), Some(Command::PublicKey(format))) => match format.as_hex {
            true => hex_address_cli(ctx, acc_ix)?,
            false => public_key_cli(ctx, acc_ix)?,
        },

        (Some(acc_ix), Some(Command::Balance(balance))) => {
            account_balance_cli(ctx, acc_ix, &balance).await?
        }
        (Some(acc_ix), Some(Command::Transfer(transfer))) => {
            transfer_cli(ctx, acc_ix, transfer).await?
        }
        (None, Some(cmd)) => print_subcmd_index_warning(&cmd),
        (None, None) => print_subcmd_help(),
    }
    Ok(())
}

pub(crate) async fn account_balance_cli(
    ctx: &crate::CliContext,
    acc_ix: usize,
    balance: &Balance,
) -> Result<()> {
    let wallet = load_wallet(&ctx.wallet_path)?;
    let provider = Provider::connect(&ctx.node_url).await?;
    let mut cached_addrs = read_cached_addresses(&wallet.crypto.ciphertext)?;
    let cached_addr = cached_addrs
        .remove(&acc_ix)
        .ok_or_else(|| anyhow!("No cached address for account {acc_ix}"))?;

    let account = if balance.unverified.unverified {
        Wallet::new_locked(cached_addr, provider)
    } else {
        let prompt = format!("Please enter your wallet password to verify account {acc_ix}: ");
        let password = rpassword::prompt_password(prompt)?;
        let account = derive_account_unlocked(&ctx.wallet_path, acc_ix, &password, &provider)?;
        verify_address_and_update_cache(acc_ix, &account, &cached_addr, &wallet.crypto.ciphertext)?;
        account.lock()
    };
    println!("Connecting to {}", &ctx.node_url);
    println!("Fetching the balance of the following account:",);
    let account_adr = checksum_encode(&format!("0x{}", account.address()))?;
    println!("  {acc_ix:>3}: {}", account_adr);
    let account_balance: BTreeMap<_, _> = account.get_balances().await?.into_iter().collect();
    println!("\nAccount {acc_ix}:");
    if account_balance.is_empty() {
        print_balance_empty(&ctx.node_url);
    } else {
        print_balance(&account_balance);
    }
    Ok(())
}

/// Display a warning to the user if the expected address differs from the account address.
/// Returns `Ok(true)` if the address matched, `Ok(false)` if it did not, `Err` if we failed to
/// update the cache.
pub(crate) fn verify_address_and_update_cache(
    acc_ix: usize,
    account: &Wallet,
    expected_addr: &Address,
    wallet_ciphertext: &[u8],
) -> Result<bool> {
    let addr = account.address();
    println_warning(&format!(
        "Cached address for account {} differs from derived address.\n\
{:>2}Cached: {}
{:>2}Derived: {}
{:>2}Updating cache with newly derived address.",
        acc_ix, "", expected_addr, "", addr, "",
    ));
    cache_address(wallet_ciphertext, acc_ix, &addr)?;
    Ok(false)
}

pub(crate) fn print_balance_empty(node_url: &Url) {
    let testnet_url = crate::network::TESTNET.parse::<Url>().unwrap();

    let faucet_url = match node_url.host_str() {
        host if host == testnet_url.host_str() => crate::network::TESTNET_FAUCET,
        _ => return println!("  Account empty."),
    };
    if node_url
        .host_str()
        .is_some_and(|a| a == crate::network::MAINNET)
    {
        println!("  Account empty.");
    } else {
        println!(
            "  Account empty. Visit the faucet to acquire some test funds: {}",
            faucet_url
        );
    }
}

pub(crate) fn print_balance(balance: &BTreeMap<String, u128>) {
    let mut table = Table::default();
    table.add_header("Asset ID");
    table.add_header("Amount");

    for (asset_id, amount) in balance {
        table
            .add_row(vec![asset_id.to_owned(), amount.to_string()])
            .expect("add_row");
    }
    println!("{}", table);
}

/// Prints a list of all known (cached) accounts for the wallet at the given path.
pub async fn print_accounts_cli(ctx: &crate::CliContext, accounts: Accounts) -> Result<()> {
    let wallet = load_wallet(&ctx.wallet_path)?;
    let addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
    if accounts.unverified.unverified {
        println!("Account addresses (unverified, printed from cache):");
        addresses
            .iter()
            .for_each(|(ix, addr)| println!("[{ix}] {addr}"));
    } else {
        let prompt = "Please enter your wallet password to verify cached accounts: ";
        let password = rpassword::prompt_password(prompt)?;
        let provider = Provider::connect(&ctx.node_url).await?;
        for &ix in addresses.keys() {
            let account = derive_account_unlocked(&ctx.wallet_path, ix, &password, &provider)?;
            let account_addr = account.address();
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
        Command::PublicKey(_) => "public-key",
        Command::Transfer(_) => "transfer",
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
pub async fn print_address(
    ctx: &crate::CliContext,
    account_ix: usize,
    unverified: bool,
) -> Result<()> {
    let wallet = load_wallet(&ctx.wallet_path)?;
    if unverified {
        let addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
        match addresses.get(&account_ix) {
            Some(address) => println!("Account {account_ix} address (unverified): {address}"),
            None => eprintln!("Account {account_ix} is not derived yet!"),
        }
    } else {
        let prompt = format!("Please enter your wallet password to verify account {account_ix}: ");
        let password = rpassword::prompt_password(prompt)?;
        let provider = Provider::connect(&ctx.node_url).await?;
        let account = derive_account_unlocked(&ctx.wallet_path, account_ix, &password, &provider)?;
        let account_addr = account.address();
        let checksum_addr = checksum_encode(&format!("0x{}", account_addr))?;
        println!("Account {account_ix} address: {checksum_addr}");
        cache_address(&wallet.crypto.ciphertext, account_ix, &account_addr)?;
    }
    Ok(())
}

/// Given a path to a wallet, an account index and the wallet's password,
/// derive the account address for the account at the given index.
pub fn derive_secret_key(
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
pub(crate) fn derive_account_unlocked(
    wallet_path: &Path,
    account_ix: usize,
    password: &str,
    provider: &Provider,
) -> Result<WalletUnlocked<PrivateKeySigner>> {
    let secret_key = derive_secret_key(wallet_path, account_ix, password)?;
    let wallet = WalletUnlocked::new(PrivateKeySigner::new(secret_key), provider.clone());
    Ok(wallet)
}

pub async fn derive_and_cache_addresses(
    ctx: &crate::CliContext,
    mnemonic: &str,
    range: Range<usize>,
) -> anyhow::Result<BTreeMap<usize, Address>> {
    let wallet = load_wallet(&ctx.wallet_path)?;
    let provider = Provider::connect(&ctx.node_url).await?;
    range
        .into_iter()
        .map(|acc_ix| {
            let derive_path = get_derivation_path(acc_ix);
            let secret_key = SecretKey::new_from_mnemonic_phrase_with_path(mnemonic, &derive_path)?;
            let account = WalletUnlocked::new(PrivateKeySigner::new(secret_key), provider.clone());
            cache_address(&wallet.crypto.ciphertext, acc_ix, &account.address())?;

            Ok(account.address().to_owned())
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|x| x.into_iter().enumerate().collect())
}

fn new_at_index(
    keystore: &EthKeystore,
    wallet_path: &Path,
    account_ix: usize,
    provider: &Provider,
) -> Result<String> {
    let prompt = format!("Please enter your wallet password to derive account {account_ix}: ");
    let password = rpassword::prompt_password(prompt)?;
    let account = derive_account_unlocked(wallet_path, account_ix, &password, provider)?;
    let account_addr = account.address();
    cache_address(&keystore.crypto.ciphertext, account_ix, &account_addr)?;
    let checksum_addr = checksum_encode(&account_addr.to_string())?;
    println!("Wallet address: {checksum_addr}");
    Ok(checksum_addr)
}

pub async fn new_at_index_cli(ctx: &crate::CliContext, account_ix: usize) -> Result<()> {
    let keystore = load_wallet(&ctx.wallet_path)?;
    let provider = Provider::connect(&ctx.node_url).await?;
    new_at_index(&keystore, &ctx.wallet_path, account_ix, &provider)?;
    Ok(())
}

pub(crate) async fn new_cli(ctx: &crate::CliContext) -> Result<()> {
    let keystore = load_wallet(&ctx.wallet_path)?;
    let addresses = read_cached_addresses(&keystore.crypto.ciphertext)?;
    let account_ix = next_derivation_index(&addresses);
    let provider = Provider::connect(&ctx.node_url).await?;
    new_at_index(&keystore, &ctx.wallet_path, account_ix, &provider)?;
    Ok(())
}

pub(crate) fn private_key_cli(ctx: &crate::CliContext, account_ix: usize) -> Result<()> {
    let prompt = format!(
        "Please enter your wallet password to display account {account_ix}'s private key: "
    );
    let password = rpassword::prompt_password(prompt)?;
    let secret_key = derive_secret_key(&ctx.wallet_path, account_ix, &password)?;
    let secret_key_string = format!("Secret key for account {account_ix}: {secret_key}\n");
    display_string_discreetly(&secret_key_string, "### Press any key to complete. ###")?;
    Ok(())
}

/// Prints the public key of given account index.
pub(crate) fn public_key_cli(ctx: &crate::CliContext, account_ix: usize) -> Result<()> {
    let prompt =
        format!("Please enter your wallet password to display account {account_ix}'s public key: ");
    let password = rpassword::prompt_password(prompt)?;
    let secret_key = derive_secret_key(&ctx.wallet_path, account_ix, &password)?;
    let public_key = PublicKey::from(&secret_key);
    println!("Public key for account {account_ix}: {public_key}");
    Ok(())
}

/// Prints the plain address for the given account index
pub(crate) fn hex_address_cli(ctx: &crate::CliContext, account_ix: usize) -> Result<()> {
    let prompt = format!(
        "Please enter your wallet password to display account {account_ix}'s plain address: "
    );
    let password = rpassword::prompt_password(prompt)?;
    let secret_key = derive_secret_key(&ctx.wallet_path, account_ix, &password)?;
    let public_key = PublicKey::from(&secret_key);
    let hashed = public_key.hash();
    let plain_address: Address = (*hashed).into();
    println!("Plain address for {}: {}", account_ix, plain_address);
    Ok(())
}

/// Transfers assets from account at a given account index to a target address.
pub(crate) async fn transfer_cli(
    ctx: &crate::CliContext,
    acc_ix: usize,
    transfer: Transfer,
) -> Result<()> {
    use fuels::accounts::Account;

    println!(
        "Preparing to transfer:\n  Amount: {}\n  Asset ID: 0x{}\n  To: {}\n",
        transfer.amount, transfer.asset_id, transfer.to
    );
    let provider = Provider::connect(&ctx.node_url).await?;

    let to = transfer.to;

    let prompt = format!(
        "Please enter your wallet password to unlock account {acc_ix} and to initiate transfer: "
    );
    let password = rpassword::prompt_password(prompt)?;
    let mut account = derive_account_unlocked(&ctx.wallet_path, acc_ix, &password, &provider)?;
    account.set_provider(provider);
    println!("Transferring...");

    let tx_response = account
        .transfer(
            to,
            transfer.amount,
            transfer.asset_id,
            TxPolicies::new(
                transfer.gas_price,
                None,
                transfer.maturity,
                None,
                None,
                transfer.gas_limit,
            ),
        )
        .await?;

    let block_explorer_url = match ctx.node_url.host_str() {
        host if host == crate::network::MAINNET.parse::<Url>().unwrap().host_str() => {
            crate::explorer::DEFAULT
        }
        host if host == crate::network::TESTNET.parse::<Url>().unwrap().host_str() => {
            crate::explorer::TESTNET
        }
        _ => "",
    };

    let tx_explorer_url = format!("{block_explorer_url}/tx/0x{}", tx_response.tx_id);
    println!(
        "\nTransfer complete!\nSummary:\n  Transaction ID: 0x{}\n  Receipts: {:#?}\n  Explorer: {}\n",
        tx_response.tx_id, tx_response.tx_status.receipts, tx_explorer_url
    );

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
pub fn cache_address(
    wallet_ciphertext: &[u8],
    account_ix: usize,
    account_addr: &Address,
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
pub(crate) fn read_cached_addresses(wallet_ciphertext: &[u8]) -> Result<AccountAddresses> {
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
            let account_addr: Address = account_addr_str
                .parse()
                .map_err(|e| anyhow!("failed to parse cached account address: {e}"))?;
            Ok((account_ix, account_addr))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{
        TEST_MNEMONIC, TEST_PASSWORD, mock_provider, with_tmp_dir_and_wallet,
    };
    use crate::utils::write_wallet_from_mnemonic_and_password;
    use fuels::types::Address;
    use std::str::FromStr;

    #[tokio::test]
    async fn create_new_account() {
        let mock_provider = mock_provider().await;

        let tmp_dir = tempfile::TempDir::new().unwrap();
        let wallet_path = tmp_dir.path().join("wallet.json");
        write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
            .unwrap();

        let wallet = derive_account_unlocked(&wallet_path, 0, TEST_PASSWORD, &mock_provider)
            .expect("wallet unlocked");
        let wallet_addr = wallet.address();
        let wallet_addr_str = wallet_addr.to_string();
        assert_eq!(
            wallet_addr_str,
            "914504548bad3ad1e2c489be3af683ede849e286bee0a349644edebc91267bde"
        );
        // Test wallet address in hex format
        assert_eq!(
            format!("{:x}", wallet_addr),
            "914504548bad3ad1e2c489be3af683ede849e286bee0a349644edebc91267bde"
        );
    }

    #[test]
    fn derive_account_by_index() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            // derive account with account index 0
            let account_ix = 0;
            let private_key = derive_secret_key(wallet_path, account_ix, TEST_PASSWORD).unwrap();
            assert_eq!(
                private_key.to_string(),
                "961bf9754dd036dd13b1d543b3c0f74062bc4ac668ea89d38ce8d712c591f5cf"
            )
        });
    }
    #[test]
    fn derive_address() {
        let address_hex = "978f983cf8210549fa92e23bff07d42e3108aa395cc961066d832e2e6a252900";
        let plain_address =
            Address::from_str(address_hex).expect("failed to create Address from hex string");
        assert_eq!(format!("{:x}", plain_address), address_hex)
    }
}
