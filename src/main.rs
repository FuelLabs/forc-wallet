mod account;
mod import;
mod new;
mod sign;
mod utils;

use crate::{
    account::{Account, Accounts},
    import::import_wallet_cli,
    new::new_wallet_cli,
    sign::Sign,
};
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[clap(name = "forc wallet", about = ABOUT, after_help = EXAMPLES, version)]
struct App {
    /// The path to a wallet. A wallet is a JSON keystore file as described in
    /// the Web3 Secret Storage Definition.
    /// By default, this is `$HOME/.fuel/wallets/.wallet`.
    /// Read more about the Web3 Secret Storage Definition here:
    /// https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage
    #[clap(long = "path")]
    wallet_path: Option<PathBuf>,
    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new wallet from a random mnemonic phrase.
    ///
    /// If a `--path` is specified, the wallet will be created at this location.
    New,
    /// Import a wallet from the provided mnemonic phrase.
    ///
    /// If a `--path` is specified, the wallet will be imported to this location.
    Import,
    /// Lists all accounts derived for the wallet so far.
    ///
    /// Note that this only includes accounts that have been previously derived
    /// *locally* and still exist within the user's `~/.fuel/wallets/accoutns`
    /// cache. If this wallet was recently imported, you may need to re-derive
    /// your accounts.
    ///
    /// By default, this requires your password in order to verify and re-
    /// derive each of the accounts. Use the `--unverified` flag to bypass
    /// this password check and read the public addresses directly from the
    /// `~/.fuel/wallets/accounts` cache.
    Accounts(Accounts),
    /// Derive a new account, sign with an existing account, or display an
    /// account's public or private key. See the `EXAMPLES` below.
    Account(Account),
    Sign(Sign),
    /// Present the sum of all account balances under a single wallet balance.
    ///
    /// Only includes accounts that have been previously derived, i.e. those
    /// that show under `forc-wallet accounts`.
    Balance(Balance),
}

#[derive(Debug, Args)]
struct Balance {
    // Account-specific args.
    #[clap(flatten)]
    account: account::Balance,
    /// Show the balance for each individual non-empty account before showing
    /// the total.
    #[clap(long)]
    accounts: bool,
}

/// The default network used in the case that none is specified.
const DEFAULT_URL: &str = BETA_2_URL;
const BETA_2_URL: &str = "https://node-beta-2.fuel.network";
const BETA_2_FAUCET_URL: &str = "https://faucet-beta-2.fuel.network";

const ABOUT: &str = "A forc plugin for generating or importing wallets using BIP39 phrases.";
const EXAMPLES: &str = r#"
EXAMPLES:
    # Create a new wallet at the default path `~/.fuel/wallets/.wallet`.
    forc wallet new

    # Import a new wallet from a mnemonic phrase.
    forc wallet import

    # Derive a new account for the default wallet.
    forc wallet account new

    # Derive a new account for the wallet at the given path.
    forc wallet --path /path/to/wallet account new

    # Derive (or re-derive) the account at index 5.
    forc wallet account 5 new

    # Sign a transaction ID with account at index 3.
    forc wallet account 3 sign tx-id 0x0bf34feb362608c4171c87115d4a6f63d1cdf4c49b963b464762329488f3ed4f

    # Sign an arbitrary string.
    forc wallet account 3 sign string "blah blah blah"

    # Sign the contents of a file.
    forc wallet account 3 sign file /path/to/data-to-sign

    # Sign a hex-encoded byte string.
    forc wallet account 3 sign hex "0xDEADBEEF"

    # You can also use the `sign` subcommand directly. The following gives the same result.
    forc wallet sign --account 3 string "blah blah blah"

    # Sign directly with a private key.
    forc wallet sign --private-key string "blah blah blah"

    # Temporarily display the private key of the account at index 0.
    forc wallet account 0 private-key

    # Show the public key of the account at index 0.
    forc wallet account 0 public-key
"#;

#[tokio::main]
async fn main() -> Result<()> {
    let app = App::parse();
    let wallet_path = app.wallet_path.unwrap_or_else(utils::default_wallet_path);
    match app.cmd {
        Command::New => new_wallet_cli(&wallet_path)?,
        Command::Import => import_wallet_cli(&wallet_path)?,
        Command::Accounts(accounts) => account::print_accounts_cli(&wallet_path, accounts)?,
        Command::Account(account) => account::cli(&wallet_path, account).await?,
        Command::Sign(sign) => sign::cli(&wallet_path, sign)?,
        Command::Balance(balance) => account::balance_cli(&wallet_path, &balance).await?,
    }
    Ok(())
}
