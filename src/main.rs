mod account;
mod import;
mod new;
mod sign;
mod utils;

use crate::{
    account::Account, import::import_wallet_cli, new::new_wallet_cli,
    sign::sign_transaction_with_private_key_cli,
};
use anyhow::Result;
use clap::{Parser, Subcommand};
use fuels::prelude::*;
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
    Accounts,
    /// Derive, sign or export the key for the account with the given index.
    Account(Account),
    /// Sign something by providing a private key *directly*, rather than with
    /// a wallet account.
    #[clap(subcommand)]
    SignPrivate(SignCmd),
}

#[derive(Debug, Subcommand)]
enum SignCmd {
    /// Sign a transaction given it's ID.
    Tx {
        /// The transaction ID.
        tx_id: fuel_types::Bytes32,
    },
}

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

    # Sign a transaction via its ID with account at index 3.
    forc wallet account 3 sign tx 0x0bf34feb362608c4171c87115d4a6f63d1cdf4c49b963b464762329488f3ed4f

    # Export the private key of the account at index 0.
    forc wallet account 0 export-private-key
"#;

#[tokio::main]
async fn main() -> Result<()> {
    let app = App::parse();
    let wallet_path = app.wallet_path.unwrap_or_else(utils::default_wallet_path);
    match app.cmd {
        Command::New => new_wallet_cli(&wallet_path)?,
        Command::Import => import_wallet_cli(&wallet_path)?,
        Command::Accounts => account::print_accounts_cli(&wallet_path)?,
        Command::Account(account) => account::cli(&wallet_path, account)?,
        Command::SignPrivate(SignCmd::Tx { tx_id }) => {
            sign_transaction_with_private_key_cli(tx_id)?
        }
    }
    Ok(())
}
