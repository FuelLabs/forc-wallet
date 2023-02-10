mod account;
mod export;
mod import;
mod init;
mod sign;
mod utils;

use std::path::PathBuf;

use crate::{
    account::{new_account_cli, print_account_address, print_account_list},
    export::export_account_cli,
    import::import_wallet_cli,
    init::init_wallet_cli,
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
    /// The path to a wallet. A wallet is a JSON keystore file as described in
    /// the Web3 Secret Storage Definition.
    /// By default, this is `$HOME/.fuel/wallets/.wallet`.
    /// Read more about the Web3 Secret Storage Definition here:
    /// https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage
    #[clap(long = "path")]
    wallet_path: Option<PathBuf>,
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
#[clap(rename_all = "kebab-case")]
enum Command {
    /// Derive a new account for the wallet.
    ///
    /// Note that upon derivation of the new account, the account's public
    /// address will be cached in plain text for convenient retrieval via the
    /// `list` and `account` commands.
    ///
    /// The index of the newly derived account will be that which succeeds the
    /// greatest known account index currently within the cache.
    New,
    /// Initialize a new wallet from a random mnemonic phrase.
    Init,
    /// Import a wallet from the provided mnemonic phrase.
    Import,
    /// Lists all accounts derived for the wallet so far.
    List,
    /// Check the wallet's account address cache for the account at the given
    /// index and print its address.
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
        Command::List => print_account_list(app.wallet_path)?,
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
