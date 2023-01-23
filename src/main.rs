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
use clap::{ArgEnum, Parser, Subcommand};
use fuels::prelude::*;

#[derive(Debug, Parser)]
#[clap(
    name = "forc-wallet",
    about = "A forc plugin for generating or importing wallets using BIP39 phrases.",
    version
)]
struct App {
    #[clap(subcommand)]
    pub command: Command,
    #[clap(arg_enum, long = "format", short = 'o', default_value = "json")]
    pub fmt: OutputFormat,
}

#[derive(Debug, Subcommand)]
#[clap(rename_all = "kebab-case")]
enum Command {
    /// Generate a new account for the initialized HD wallet.
    New {
        #[clap(long)]
        path: Option<PathBuf>,
    },
    /// Initialize the HD wallet from a random mnemonic phrase.
    Init {
        #[clap(long)]
        path: Option<PathBuf>,
    },
    /// Initialize the HD wallet from the provided mnemonic phrase.
    Import {
        #[clap(long)]
        path: Option<PathBuf>,
    },
    /// Lists all accounts derived so far.
    List {
        #[clap(long)]
        path: Option<PathBuf>,
    },
    /// Get the address of an acccount from account index
    Account {
        #[clap(long)]
        account_index: usize,
        #[clap(long)]
        path: Option<PathBuf>,
    },
    /// Sign a transaction by providing its ID and the signing account's index
    Sign {
        #[clap(long)]
        id: String,
        #[clap(long)]
        account_index: usize,
        #[clap(long)]
        path: Option<PathBuf>,
    },
    /// Sign a transaction by providing its ID and the signing account's private key.
    SignPrivate {
        #[clap(long)]
        tx_id: String,
    },
    /// Get the private key of an account from its index
    Export {
        #[clap(long)]
        path: Option<PathBuf>,
        #[clap(long)]
        account_index: usize,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
#[clap(rename_all = "kebab-case")]
enum OutputFormat {
    Json,
    Toml,
}

#[tokio::main]
async fn main() -> Result<()> {
    let app = App::parse();

    match app.command {
        Command::New { path } => new_account_cli(path)?,
        Command::List { path } => print_wallet_list(path)?,
        Command::Init { path } => init_wallet_cli(path)?,
        Command::Account {
            account_index,
            path,
        } => print_account_address(path, account_index)?,
        Command::Sign {
            id,
            account_index,
            path,
        } => sign_transaction_cli(&id, account_index, path)?,
        Command::Import { path } => import_wallet_cli(path)?,
        Command::Export {
            path,
            account_index,
        } => export_account_cli(path, account_index)?,
        Command::SignPrivate { tx_id } => sign_transaction_with_private_key_cli(&tx_id)?,
    };
    Ok(())
}
