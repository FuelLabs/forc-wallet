use anyhow::{anyhow, bail, Result};
use clap::{ArgEnum, Parser, Subcommand};
use fuels::prelude::*;
use fuels::signers::wallet::Wallet;
use std::{
    collections::HashMap,
    io::{stdout, Write},
    path::PathBuf,
};
use termion::screen::AlternateScreen;

const DEFAULT_WALLETS_VAULT_PATH: &str = ".fuel/wallets/";

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
    /// Get the address of an account given its index
    Account {
        /// Account index
        account_index: usize,
    },
    /// Import a wallet from mnemonic phrase
    Import {
        /// The Bip39 phrase to import the wallet from
        phrase: String,
    },
    /// Lists all wallets stored in ~/.fuel/wallets/.
    List,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
#[clap(rename_all = "kebab-case")]
enum OutputFormat {
    Json,
    Toml,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = App::parse();

    match app.command {
        Command::New { path } => create_wallet(path).await,
        Command::Account { account_index } => get_account_address(account_index)?,
        Command::Import { phrase } => import_wallet(phrase).await,
        Command::List => list_wallets()?,
    };

    Ok(())
}

async fn create_wallet(path: Option<PathBuf>) {
    // Generate wallet from mnenomic phrase.
    let mnemonic = Wallet::generate_mnemonic_phrase(&mut rand::thread_rng(), 12).unwrap();
    let wallet = Wallet::new_from_mnemonic_phrase(&mnemonic, None).unwrap();

    let password =
        rpassword::prompt_password("Please enter a password to encrypt this private key: ")
            .unwrap();

    let confirmation = rpassword::prompt_password("Please confirm your password: ").unwrap();

    if password != confirmation {
        println!("Passwords do not match -- try again!");
        std::process::exit(1);
    }

    // Wallets are created in ~/.fuel/wallets/ following the format below:
    // <index>_<public_address>/<uuid>.
    // The index is the wallet's index in the list of wallets.
    let path = path.unwrap_or_else(|| {
        let mut path = home::home_dir().unwrap();
        path.push(DEFAULT_WALLETS_VAULT_PATH);
        path.push(format!(
            "{}_{}",
            get_next_wallet_index().unwrap(),
            wallet.address()
        ));

        // create directory if it doesn't exist.
        if !path.exists() {
            std::fs::create_dir_all(&path).unwrap();
        }

        path
    });

    // Encrypt the wallet and store it in the vault.
    let uuid = wallet.encrypt(path, password).unwrap();

    // Prints to an alternate screen.
    // This prevents the mnemonic phrase from being printed to the terminal.
    let mut screen = AlternateScreen::from(stdout());
    writeln!(screen, "JSON Wallet uuid: {}\n", uuid).unwrap();
    writeln!(screen, "Wallet public address: {}\n", wallet.address()).unwrap();
    writeln!(screen, "Wallet mnemonic phrase: {}\n", mnemonic).unwrap();
    screen.flush().unwrap();

    let mut input = String::new();
    println!("### Do not share or lose this mnemonic phrase! Press any key to complete. ###");
    std::io::stdin().read_line(&mut input).unwrap();
}

async fn import_wallet(phrase: String) {
    let wallet = Wallet::new_from_mnemonic_phrase(&phrase, None).unwrap();

    println!("Wallet imported: {}", wallet.address());
}

fn with_traverse_wallets<F>(f: &mut F) -> Result<()>
where
    F: FnMut(Option<&String>, Option<&String>) -> Result<()>,
{
    let mut path = home::home_dir().unwrap();
    path.push(DEFAULT_WALLETS_VAULT_PATH);

    for dir in std::fs::read_dir(path)? {
        let path = dir?.path();
        if path.is_dir() {
            if let Some(last_component) = path.components().last() {
                let split: Vec<String> = last_component
                    .as_os_str()
                    .to_str()
                    .ok_or_else(|| anyhow!("Wroing wallet path: {:?}", path))?
                    .split('_')
                    .map(|s| s.to_string())
                    .collect();
                // Call given function
                f(split.first(), split.last())?;
            }
        }
    }
    Ok(())
}

/// Walks through ~/.fuel/wallets/ and returns the next index based
/// on the number of wallets in the vault.
fn get_next_wallet_index() -> Result<usize> {
    let mut highest_index = 0;
    with_traverse_wallets(&mut |index, _| {
        if let Some(index) = index {
            let index = index.parse::<usize>()?;
            if index > highest_index {
                highest_index = index;
            }
        }
        Ok(())
    })?;
    Ok(highest_index + 1)
}

/// Collect all wallets in the DEFAULT_WALLETS_VAULT_PATH
///
/// Returns a map between wallet index and wallet address
fn collect_all_wallets() -> Result<HashMap<usize, String>> {
    let mut wallets = HashMap::new();
    with_traverse_wallets(&mut |index, address| {
        if let (Some(index), Some(address)) = (index, address) {
            let index = index.parse::<usize>()?;
            wallets.insert(index, address.clone());
        }
        Ok(())
    })?;
    Ok(wallets)
}

/// Print account address of a given account index.
fn get_account_address(wallet_index: usize) -> Result<()> {
    let wallets = collect_all_wallets()?;

    let wallet = wallets.get(&wallet_index);
    match wallet {
        Some(wallet) => {
            println!("0x{}", wallet);
        }
        None => {
            bail!("Wallet index {} does not exists", wallet_index);
        }
    }

    Ok(())
}

fn list_wallets() -> Result<()> {
    let wallets = collect_all_wallets()?;

    // Sort the wallets by index.
    let mut sorted_wallets = wallets.into_iter().collect::<Vec<_>>();
    sorted_wallets.sort_by(|a, b| a.0.cmp(&b.0));

    // Print the wallets.
    for (index, address) in sorted_wallets {
        println!("[{}].         0x{}", index, address);
    }
    Ok(())
}
