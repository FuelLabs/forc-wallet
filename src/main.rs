mod account;
mod import;
mod new;
mod sign;
mod utils;

use crate::{
    import::import_wallet_cli,
    new::new_wallet_cli,
    sign::{sign_transaction_cli, sign_transaction_with_private_key_cli},
};
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use fuels::prelude::*;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[clap(name = "forc wallet", about = ABOUT, after_help = EXAMPLES, version)]
struct App {
    /// The path to a wallet. A wallet is a JSON keystore file as described in
    /// the Web3 Secret Storage Definition.
    /// By default, this is `$HOME/.fuel/wallets/.wallet`.
    /// Read more about the Web3 Secret Storage Definition here:
    /// https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage
    #[clap(long = "path")]
    wallet_path: Option<PathBuf>,
    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new wallet from a random mnemonic phrase.
    ///
    /// If a `--path` is specified, the wallet will be created at this location.
    New,
    /// Import a wallet from the provided mnemonic phrase.
    ///
    /// If a `--path` is specified, the wallet will be imported to this location.
    Import,
    /// Lists all accounts derived for the wallet so far.
    ///
    /// Note that this only includes accounts that have been previously derived
    /// *locally* and still exist within the user's `~/.fuel/wallets/accoutns`
    /// cache. If this wallet was recently imported, you may need to re-derive
    /// your accounts.
    Accounts,
    /// Derive, sign or export the key for the account with the given index.
    Account(Account),
    /// Sign something by providing a private key *directly*, rather than with
    /// a wallet account.
    #[clap(subcommand)]
    SignPrivate(SignCmd),
}

#[derive(Debug, Args)]
struct Account {
    /// The index of the account.
    ///
    /// This index is used directly within the path used to derive the account.
    index: Option<usize>,
    #[clap(subcommand)]
    cmd: Option<AccountCmd>,
}

#[derive(Debug, Subcommand)]
enum AccountCmd {
    /// Derive and reveal a new account for the wallet.
    ///
    /// Note that upon derivation of the new account, the account's public
    /// address will be cached in plain text for convenient retrieval via the
    /// `accounts` and `account <ix>` commands.
    ///
    /// The index of the newly derived account will be that which succeeds the
    /// greatest known account index currently within the cache.
    New,
    /// Sign a transaction with the specified account.
    #[clap(subcommand)]
    Sign(SignCmd),
    /// Export the private key of an account from its index.
    ///
    /// WARNING: This prints your account's private key to stdout!
    ExportPrivateKey,
}

#[derive(Debug, Subcommand)]
enum SignCmd {
    /// Sign a transaction given it's ID.
    Tx {
        /// The transaction ID.
        tx_id: fuel_types::Bytes32,
    },
}

const ABOUT: &str = "A forc plugin for generating or importing wallets using BIP39 phrases.";
const EXAMPLES: &str = r#"
EXAMPLES:
    # Create a new wallet at the default path `~/.fuel/wallets/.wallet`.
    forc wallet new

    # Import a new wallet from a mnemonic phrase.
    forc wallet import

    # Derive a new account for the default wallet.
    forc wallet account new

    # Derive a new account for the wallet at the given path.
    forc wallet --path /path/to/wallet account new

    # Derive (or re-derive) the account at index 5.
    forc wallet account 5 new

    # Sign a transaction via its ID with account at index 3.
    forc wallet account 3 sign tx 0x0bf34feb362608c4171c87115d4a6f63d1cdf4c49b963b464762329488f3ed4f

    # Export the private key of the account at index 0.
    forc wallet account 0 export-private-key
"#;

#[tokio::main]
async fn main() -> Result<()> {
    let app = App::parse();
    let wallet_path = app.wallet_path.unwrap_or_else(utils::default_wallet_path);
    match app.cmd {
        Command::New => new_wallet_cli(&wallet_path)?,
        Command::Import => import_wallet_cli(&wallet_path)?,
        Command::Accounts => account::print_address_list(&wallet_path)?,
        Command::Account(Account { index, cmd }) => match (index, cmd) {
            (None, Some(AccountCmd::New)) => account::new_cli(&wallet_path)?,
            (Some(acc_ix), Some(AccountCmd::New)) => {
                account::new_at_index_cli(&wallet_path, acc_ix)?
            }
            (Some(acc_ix), None) => account::print_address(&wallet_path, acc_ix)?,
            (Some(acc_ix), Some(AccountCmd::Sign(SignCmd::Tx { tx_id }))) => {
                sign_transaction_cli(&wallet_path, tx_id, acc_ix)?
            }
            (Some(acc_ix), Some(AccountCmd::ExportPrivateKey)) => {
                account::export_cli(&wallet_path, acc_ix)?
            }
            (None, Some(cmd)) => print_account_subcmd_index_warning(&cmd),
            (None, None) => print_account_subcmd_help(),
        },
        Command::SignPrivate(SignCmd::Tx { tx_id }) => {
            sign_transaction_with_private_key_cli(tx_id)?
        }
    }
    Ok(())
}

fn print_account_subcmd_help() {
    // The user must provide either the account index or a `New`
    // command - otherwise we print the help output for the
    // `account` subcommand. There doesn't seem to be a nice way
    // of doing this with clap's derive API, so we do-so with a
    // child process.
    std::process::Command::new("forc-wallet")
        .args(["account", "--help"])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output()
        .expect("failed to invoke `forc wallet account --help` command");
}

fn print_account_subcmd_index_warning(cmd: &AccountCmd) {
    let cmd_str = match cmd {
        AccountCmd::Sign(_) => "sign",
        AccountCmd::ExportPrivateKey => "export-private-key",
        AccountCmd::New => unreachable!("new is valid without an index"),
    };
    eprintln!(
        "Error: The command `{cmd_str}` requires an account index. \
        For example: `forc wallet account <INDEX> {cmd_str} ...`\n"
    );
    print_account_subcmd_help();
}
