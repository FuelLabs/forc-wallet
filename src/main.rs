mod create;
mod list;
mod utils;

use crate::create::{new_account, new_wallet, DEFAULT_WALLETS_VAULT_PATH};
use crate::list::print_wallet_list;
use anyhow::{bail, Result};
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
    /// Randomly generate a new wallet or create the next account for the given wallet. By default, wallets are stored in ~/.fuel/wallets/. Initializing a new HD wallet removes old vault
    New {
        #[clap(long)]
        path: Option<String>,
        /// Init a new HD wallet
        #[clap(long)]
        wallet: bool,
        /// Create a new account with given phrase
        #[clap(long)]
        account: bool,
        /// The Bip39 phrase to import a wallet from, if not provided it will be randomly generated
        #[clap(long)]
        phrase: Option<String>,
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
async fn main() -> Result<()> {
    let app = App::parse();

    match app.command {
        Command::New {
            path,
            wallet,
            account,
            phrase,
        } => new_cli(path, wallet, account, phrase)?,
        Command::List { path } => {
            print_wallet_list(path.unwrap_or_else(|| DEFAULT_WALLETS_VAULT_PATH.to_string()))?
        }
    };
    Ok(())
}

fn new_cli(
    path: Option<String>,
    wallet: bool,
    account: bool,
    phrase: Option<String>,
) -> Result<()> {
    if !wallet && !account {
        bail!("Either --wallet or --account needed!");
    }
    if wallet {
        new_wallet(path, phrase)?;
    } else if phrase.is_none() {
        bail!("To create an account --phrase needs to be provided!");
    } else {
        let phrase = phrase.unwrap();
        let (wallet, uuid) = new_account(&phrase, path)?;
        println!("Account created.");
        println!("JSON Wallet uuid: {}\n", uuid);
        println!("Wallet public address: {}\n", wallet.address());
    }
    Ok(())
}
