mod create;
mod list;
mod utils;

use crate::create::{create_wallet, DEFAULT_WALLETS_VAULT_PATH};
use crate::list::{get_next_wallet_index, print_wallet_list};
use clap::{ArgEnum, Parser, Subcommand};
use fuels::prelude::*;
use fuels::signers::wallet::Wallet;
use std::path::PathBuf;

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
    /// Randomly generate a new wallet. By default, wallets are stored in ~/.fuel/wallets/.
    New {
        #[clap(required = false, parse(from_os_str))]
        path: Option<PathBuf>,
    },
    /// Import a wallet from mnemonic phrase
    Import {
        /// The Bip39 phrase to import the wallet from
        phrase: String,
    },
    /// Lists all wallets stored in `path`, or in `~/.fuel/wallets/`.
    List { path: Option<String> },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
#[clap(rename_all = "kebab-case")]
enum OutputFormat {
    Json,
    Toml,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let app = App::parse();

    let _ = match app.command {
        Command::New { path } => create_wallet(path).await,
        Command::Import { phrase } => import_wallet(phrase).await,
        Command::List { path } => {
            print_wallet_list(path.unwrap_or_else(|| DEFAULT_WALLETS_VAULT_PATH.to_string()))
        }
    };
    Ok(())
}

async fn import_wallet(phrase: String) -> Result<(), Error> {
    let wallet = Wallet::new_from_mnemonic_phrase(&phrase, None).unwrap();

    println!("Wallet imported: {}", wallet.address());
    Ok(())
}
