use bip39::Language::English;
use bip39::{Mnemonic, MnemonicType, Seed};
use clap::{ArgEnum, Parser, Subcommand};
use fuel_crypto::{Hasher, SecretKey};
use fuel_types::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[clap(
    name = "forc-wallet",
    about = "Forc plugin for generating and saving Fuel wallets",
    version
)]
struct App {
    #[clap(subcommand)]
    pub command: Command,
    #[clap(arg_enum, default_value = "json")]
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
        OutputFormat::Json => serde_json::to_string(&wallet).unwrap(),
        OutputFormat::Toml => toml::to_string(&wallet).unwrap(),
    };

    println!("{}", wallet);
}

#[derive(Serialize, Deserialize)]
struct Wallet {
    mnemonic: String,
    secret: SecretKey,
    address: Address,
}

impl From<Mnemonic> for Wallet {
    fn from(mnemonic: Mnemonic) -> Self {
        let seed = Seed::new(&mnemonic, "");
        let seed_bytes: &[u8] = seed.as_bytes();
        let secret_bytes = Hasher::hash(seed_bytes);
        let secret = SecretKey::try_from(secret_bytes).unwrap();
        let public_key = secret.public_key();
        let address = Address::from(*public_key.hash());
        Self {
            mnemonic: mnemonic.phrase().to_string(),
            secret,
            address,
        }
    }
}
