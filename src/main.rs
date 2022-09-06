mod account;
mod init;
mod list;
mod sign;
mod utils;

use crate::{
    account::{new_account, print_account},
    init::init_wallet,
    list::print_wallet_list,
    sign::sign_transaction_manually,
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
    New { path: Option<String> },
    /// Initialize the HD wallet. If it is already initialized this will remove the old one.
    Init {
        #[clap(long)]
        import: bool,
        #[clap(long)]
        path: Option<String>,
    },
    /// Lists all accounts derived so far.
    List { path: Option<String> },
    /// Get the address of an acccount from account index
    Account {
        account_index: usize,
        #[clap(long)]
        export: bool,
        #[clap(long)]
        path: Option<String>,
    },
    /// Sign a transaction by providing its ID and the signing account's index
    Sign {
        id: String,
        account_index: usize,
        path: Option<String>,
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
        Command::New { path } => new_account(path)?,
        Command::List { path } => print_wallet_list(path)?,
        Command::Init { import, path } => init_wallet(import, path)?,
        Command::Account {
            account_index,
            export,
            path,
        } => print_account(path, account_index, export)?,
        Command::Sign {
            id,
            account_index,
            path,
        } => sign_transaction_manually(&id, account_index, path).await?,
    };
    Ok(())
}
