use clap::{ArgEnum, Parser, Subcommand};
use fuels::prelude::*;
use fuels::signers::wallet::Wallet;
use std::collections::HashMap;
use std::io::stdout;
use std::io::Write;
use std::path::PathBuf;
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
        Command::Import { phrase } => import_wallet(phrase).await,
        Command::List => list_wallets(),
    };

    Ok(())
}

async fn create_wallet(path: Option<PathBuf>) {
    // Generate wallet from mnenomic phrase.
    let mnemonic = Wallet::generate_mnemonic_phrase(&mut rand::thread_rng(), 12).unwrap();

    let wallet = Wallet::new_from_mnemonic_phrase(&mnemonic, None).unwrap();

    let password = request_password();
    let path = path.unwrap_or_else(|| get_default_wallet_path(wallet.address()));

    // Encrypt the wallet and store it in the vault.
    let uuid = wallet.encrypt(path, password).unwrap();

    report_discretely(mnemonic, wallet, uuid);
}

// Prints to an alternate screen.
// This prevents the mnemonic phrase from being printed to the terminal.
fn report_discretely(mnemonic: String, wallet: Wallet, uuid: String) {
    let mut screen = AlternateScreen::from(stdout());
    writeln!(screen, "JSON Wallet uuid: {}\n", uuid).unwrap();
    writeln!(screen, "Wallet public address: {}\n", wallet.address()).unwrap();
    writeln!(screen, "Wallet mnemonic phrase: {}\n", mnemonic).unwrap();
    screen.flush().unwrap();

    println!("### Do not share or lose this mnemonic phrase! Press any key to complete. ###");
    wait_for_keypress();
}

fn wait_for_keypress() {
    let mut single_key = [0u8];
    io::stdin().read_exact(&mut single_key).unwrap();
}

fn request_password() -> String {
    let password =
        rpassword::prompt_password("Please enter a password to encrypt this private key: ")
            .unwrap();

    let confirmation = rpassword::prompt_password("Please confirm your password: ").unwrap();

    if password != confirmation {
        println!("Passwords do not match -- try again!");
        std::process::exit(1);
    }
    password
}


async fn import_wallet(phrase: String) {
    let wallet = Wallet::new_from_mnemonic_phrase(&phrase, None).unwrap();

    println!("Wallet imported: {}", wallet.address());
}

// Walks through ~/.fuel/wallets/ and returns the next index based
// on the number of wallets in the vault.
fn get_next_wallet_index() -> usize {
    let mut path = home::home_dir().unwrap();
    path.push(DEFAULT_WALLETS_VAULT_PATH);

    let dirs = match std::fs::read_dir(path) {
        Ok(dirs) => dirs,
        Err(_) => {
            return 0;
        }
    };

    let mut highest_index = 0;
    for dir in dirs {
        let dir = dir.unwrap();
        let path = dir.path();

        if path.is_dir() {
            let last_component = path.components().last().unwrap();
            let split: Vec<&str> = last_component
                .as_os_str()
                .to_str()
                .unwrap()
                .split('_')
                .collect();
            let index = split.first().unwrap().parse::<usize>().unwrap();
            if index > highest_index {
                highest_index = index;
            }
        }
    }

    highest_index + 1
}

fn list_wallets() {
    let mut path = home::home_dir().unwrap();
    path.push(DEFAULT_WALLETS_VAULT_PATH);

    // list directories in the path
    let dirs = match std::fs::read_dir(path) {
        Ok(dirs) => dirs,
        Err(_) => {
            println!("No wallets found.");
            return;
        }
    };

    let mut wallets = HashMap::new();

    println!("Num.         Address.");
    for dir in dirs {
        let dir = dir.unwrap();
        let path = dir.path();

        if path.is_dir() {
            // get the last component of the path
            let last_component = path.components().last().unwrap();
            let split: Vec<String> = last_component
                .as_os_str()
                .to_str()
                .unwrap()
                .split('_')
                .map(|s| s.to_string())
                .collect();

            let index = split.first().unwrap().clone().parse::<usize>().unwrap();
            let address = split.last().unwrap().clone();
            let s = format!("[{}].         0x{}", index, address);
            wallets.insert(index, s);
        }
    }

    // Sort the wallets by index.
    let mut sorted_wallets = wallets.into_iter().collect::<Vec<_>>();
    sorted_wallets.sort_by(|a, b| a.0.cmp(&b.0));

    // Print the wallets.
    for wallet in sorted_wallets {
        println!("{}", wallet.1);
    }
}
