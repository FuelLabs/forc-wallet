use anyhow::Result;
use clap::{Parser, Subcommand};
use forc_tracing::{init_tracing_subscriber, println_error};
use forc_wallet::{
    CliContext,
    account::{self, Account, Accounts},
    balance::{self, Balance},
    export::export_wallet_cli,
    import::{Import, import_wallet_cli},
    list::{List, list_wallet_cli},
    network::DEFAULT as DEFAULT_NODE_URL,
    new::{New, new_wallet_cli},
    sign::{self, Sign},
    utils::default_wallet_path,
};
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Parser)]
#[clap(name = "forc wallet", about = ABOUT, after_long_help = EXAMPLES, version)]
struct App {
    /// The path to a wallet. A wallet is a JSON keystore file as described in
    /// the Web3 Secret Storage Definition.
    /// Read more about the Web3 Secret Storage Definition here:
    /// https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage
    #[clap(long = "path", default_value_os_t = default_wallet_path() )]
    wallet_path: PathBuf,

    /// The URL of the Fuel node to connect to.
    #[clap(long, default_value_t = Url::parse(DEFAULT_NODE_URL).unwrap())]
    node_url: Url,

    #[clap(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new wallet from a random mnemonic phrase.
    ///
    /// If a `--path` is specified, the wallet will be created at this location.
    ///
    /// If a '--fore' is specified, will automatically removes the existing wallet at the same
    /// path.
    New(New),
    /// List all wallets in the default wallet directory.
    List(List),
    /// Import a wallet from the provided mnemonic phrase.
    ///
    /// If a `--path` is specified, the wallet will be imported to this location.
    ///
    /// If a '--fore' is specified, will automatically removes the existing wallet at the same
    /// path.
    Import(Import),
    /// Export a wallet as a mnemonic phrase.
    ///
    /// If a `--path` is specified, the wallet will be read from that location.
    Export,
    /// Lists all accounts derived for the wallet so far.
    ///
    /// Note that this only includes accounts that have been previously derived
    /// *locally* and still exist within the user's `~/.fuel/wallets/accoutns`
    /// cache. If this wallet was recently imported, you may need to re-derive
    /// your accounts.
    ///
    /// By default, this requires your password in order to verify and re-
    /// derive each of the accounts. Use the `--unverified` flag to bypass
    /// this password check and read the public addresses directly from the
    /// `~/.fuel/wallets/accounts` cache.
    Accounts(Accounts),
    /// Derive a new account, sign with an existing account, or display an
    /// account's public or private key. See the `EXAMPLES` below.
    Account(Account),
    Sign(Sign),
    /// Present the sum of all account balances under a single wallet balance.
    ///
    /// Only includes accounts that have been previously derived, i.e. those
    /// that show under `forc-wallet accounts`.
    Balance(Balance),
}

const ABOUT: &str = "A forc plugin for generating or importing wallets using BIP39 phrases.";
const EXAMPLES: &str = r#"
EXAMPLES:
    # Create a new wallet at the default path `~/.fuel/wallets/.wallet`.
    forc wallet new

    # Create a new wallet and automatically replace the existing wallet if it's at the same path.
    forc wallet new --force

    # Import a new wallet from a mnemonic phrase.
    forc wallet import

    # Export wallet as a mnemonic phrase from default path.
    forc wallet import

    # Export wallet as a mnemonic phrase read from the given path.
    forc wallet import --path /path/to/wallet

    # Import a new wallet from a mnemonic phrase and automatically replace the existing wallet if it's at the same path.
    forc wallet import --force

    # Derive a new account for the default wallet.
    forc wallet account new

    # Derive a new account for the wallet at the given path.
    forc wallet --path /path/to/wallet account new

    # Derive (or re-derive) the account at index 5.
    forc wallet account 5 new

    # Sign a transaction ID with account at index 3.
    forc wallet account 3 sign tx-id 0x0bf34feb362608c4171c87115d4a6f63d1cdf4c49b963b464762329488f3ed4f

    # Sign an arbitrary string.
    forc wallet account 3 sign string "blah blah blah"

    # Sign the contents of a file.
    forc wallet account 3 sign file /path/to/data-to-sign

    # Sign a hex-encoded byte string.
    forc wallet account 3 sign hex "0xDEADBEEF"

    # You can also use the `sign` subcommand directly. The following gives the same result.
    forc wallet sign --account 3 string "blah blah blah"

    # Sign directly with a private key.
    forc wallet sign --private-key string "blah blah blah"

    # Temporarily display the private key of the account at index 0.
    forc wallet account 0 private-key

    # Show the public key of the account at index 0.
    forc wallet account 0 public-key

    # Transfer 1 token of the base asset id to an address at the gas price of 1.
    forc wallet account 0 transfer --to 0x0b8d0f6a7f271919708530d11bdd9398205137e012424b611e9d97118c180bea
    --amount 1 --asset-id 0x0000000000000000000000000000000000000000000000000000000000000000 --gas-price 1
"#;

#[tokio::main]
async fn main() {
    init_tracing_subscriber(Default::default());
    if let Err(err) = run().await {
        println_error(&format!("{}", err));
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let app = App::parse();
    let ctx = CliContext {
        wallet_path: app.wallet_path,
        node_url: app.node_url,
    };
    match app.cmd {
        Command::New(new) => new_wallet_cli(&ctx, new).await?,
        Command::List(list) => list_wallet_cli(&ctx, list).await?,
        Command::Import(import) => import_wallet_cli(&ctx, import).await?,
        Command::Export => export_wallet_cli(&ctx.wallet_path)?,
        Command::Accounts(accounts) => account::print_accounts_cli(&ctx, accounts).await?,
        Command::Account(account) => account::cli(&ctx, account).await?,
        Command::Sign(sign) => sign::cli(&ctx, sign)?,
        Command::Balance(balance) => balance::cli(&ctx, &balance).await?,
    }
    Ok(())
}
