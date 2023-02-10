mod account;
mod export;
mod import;
mod init;
mod list;
mod sign;
mod utils;

use std::path::PathBuf;

use crate::{
    account::{new_account_cli, print_account_address},
    export::export_account_cli,
    import::import_wallet_cli,
    init::init_wallet_cli,
    list::print_wallet_list,
    sign::{sign_transaction_cli, sign_transaction_with_private_key_cli},
};
use anyhow::Result;
use clap::{Parser, Subcommand};
use fuels::prelude::*;

#[derive(Debug, Parser)]
#[clap(
    name = "forc-wallet",
    about = "A forc plugin for generating or importing wallets using BIP39 phrases.",
    version
)]
struct App {
    /// The path to a wallet directory. A wallet directory is a directory
    /// associated with a single wallet and contains an associated `.wallet`
    /// JSON keystore file. It may also contain an `.accounts` JSON file
    /// containing a list of accounts that have been known to be derived so
    /// far.
    /// By default, this is `$HOME/.fuel/wallets/default`.
    #[clap(long = "path")]
    wallet_path: Option<PathBuf>,
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
#[clap(rename_all = "kebab-case")]
enum Command {
    /// Generate a new account for the initialized HD wallet.
    New,
    /// Initialize the HD wallet from a random mnemonic phrase.
    Init,
    /// Initialize the HD wallet from the provided mnemonic phrase.
    Import,
    /// Lists all accounts derived so far.
    List,
    /// Get the address of an account from account index
    Account {
        /// The index of the account to show.
        #[clap(long)]
        index: usize,
    },
    /// Sign a transaction by providing its ID and the signing account's index
    Sign {
        #[clap(long)]
        id: String,
        #[clap(long)]
        account_index: usize,
    },
    /// Sign a transaction by providing its ID and the signing account's private key.
    SignPrivate {
        #[clap(long)]
        tx_id: String,
    },
    /// Get the private key of an account from its index
    Export {
        #[clap(long)]
        account_index: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let app = App::parse();

    match app.command {
        Command::New => new_account_cli(app.wallet_path)?,
        Command::List => print_wallet_list(app.wallet_path)?,
        Command::Init => init_wallet_cli(app.wallet_path)?,
        Command::Account { index } => print_account_address(app.wallet_path, index)?,
        Command::Sign { id, account_index } => {
            sign_transaction_cli(&id, account_index, app.wallet_path)?
        }
        Command::Import => import_wallet_cli(app.wallet_path)?,
        Command::Export { account_index } => export_account_cli(app.wallet_path, account_index)?,
        Command::SignPrivate { tx_id } => sign_transaction_with_private_key_cli(&tx_id)?,
    };
    Ok(())
}
