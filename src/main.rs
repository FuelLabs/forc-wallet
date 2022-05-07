use crate::wallet::Wallet;
use bip39::{Language::English, Mnemonic, MnemonicType};
use clap::{ArgEnum, Parser, Subcommand};

pub(crate) mod wallet;

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
    /// Randomly generate a new wallet
    Generate,
    /// Import a wallet from mnemonic phrase
    Import {
        /// The Bip39 phrase to import the wallet from
        phrase: String,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
#[clap(rename_all = "kebab-case")]
enum OutputFormat {
    Json,
    Toml,
}

fn main() -> anyhow::Result<()> {
    let app = App::parse();

    let mnemonic = match app.command {
        Command::Generate => generate(),
        Command::Import { phrase } => import_phrase(phrase)?,
    };

    print_wallet(mnemonic.into(), app.fmt);
    Ok(())
}

fn generate() -> Mnemonic {
    Mnemonic::new(MnemonicType::Words12, English)
}

fn import_phrase(phrase: String) -> anyhow::Result<Mnemonic> {
    Mnemonic::from_phrase(&phrase, English)
}

fn print_wallet(wallet: Wallet, fmt: OutputFormat) {
    let wallet = match fmt {
        OutputFormat::Json => serde_json::to_string_pretty(&wallet).unwrap(),
        OutputFormat::Toml => toml::to_string(&wallet).unwrap(),
    };

    println!("{}", wallet);
}
