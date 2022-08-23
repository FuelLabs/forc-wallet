use crate::list::get_wallets_list;
use crate::utils::clear_wallets_vault;
use anyhow::Result;
use fuels::prelude::*;
use fuels::signers::wallet::Wallet;
use std::io::stdout;
use std::io::Write;
use std::path::PathBuf;
use termion::screen::AlternateScreen;

pub(crate) const DEFAULT_WALLETS_VAULT_PATH: &str = ".fuel/wallets/";

/// Walks through the wallets vault directory and returns the next index based on the number of
/// wallets in the vault.
pub(crate) fn get_next_wallet_index(dir: &str) -> Result<usize, Error> {
    let sorted_wallets = get_wallets_list(dir)?;
    if let Some(last) = sorted_wallets.last() {
        Ok(last.0 + 1)
    } else {
        Ok(0)
    }
}

pub(crate) fn new_account(phrase: &str, path: Option<String>) -> Result<(Wallet, String)> {
    let wallet_path = match &path {
        Some(path) => PathBuf::from(path),
        None => home::home_dir().unwrap().join(DEFAULT_WALLETS_VAULT_PATH),
    };
    let account_index =
        get_next_wallet_index(&path.unwrap_or_else(|| DEFAULT_WALLETS_VAULT_PATH.to_string()))?;
    let derive_path = format!("m/44'/60'/{}'/0/0", account_index);
    let wallet = Wallet::new_from_mnemonic_phrase_with_path(phrase, None, &derive_path)?;

    let password =
        rpassword::prompt_password("Please enter a password to encrypt this private key: ")
            .unwrap();

    let confirmation = rpassword::prompt_password("Please confirm your password: ").unwrap();

    if password != confirmation {
        println!("Passwords do not match -- try again!");
        std::process::exit(1);
    }

    // TODO: check that the path has the right index??? not rly sure
    // Wallets are created in ~/.fuel/wallets/ or the given path following the format below:
    // <index>_<public_address>/<uuid>.
    // The index is the wallet's index in the list of wallets.
    let wallet_path = wallet_path.join(format!(
        "{}_{}",
        get_next_wallet_index(DEFAULT_WALLETS_VAULT_PATH).unwrap(),
        wallet.address()
    ));

    // create directory if it doesn't exist.
    if !wallet_path.exists() {
        std::fs::create_dir_all(&wallet_path).unwrap();
    }

    // Encrypt the wallet and store it in the vault.
    let uuid = wallet.encrypt(wallet_path, password).unwrap();

    Ok((wallet, uuid))
}

pub(crate) fn new_wallet(path: Option<String>, phrase: Option<String>) -> Result<()> {
    match &path {
        Some(path) => {
            // If the provided path does not exists create it
            std::fs::create_dir_all(path)?;
            // If the provided path exists but used clear it
            clear_wallets_vault(PathBuf::from(path))?;
        }
        None => {
            let mut path = home::home_dir().unwrap();
            path.push(DEFAULT_WALLETS_VAULT_PATH);
            // If the default vault path does not exists create it
            std::fs::create_dir_all(&path)?;
            // If the default vault path exists but used clear it
            clear_wallets_vault(path)?;
        }
    };

    // Generate wallet from mnenomic phrase.
    let mnemonic = match phrase {
        Some(phrase) => phrase,
        None => Wallet::generate_mnemonic_phrase(&mut rand::thread_rng(), 12)?,
    };
    let (wallet, uuid) = new_account(&mnemonic, path)?;
    // Prints to an alternate screen.
    // This prevents the mnemonic phrase from being printed to the terminal.
    let mut screen = AlternateScreen::from(stdout());
    writeln!(screen, "JSON Wallet uuid: {}\n", uuid)?;
    writeln!(screen, "Wallet public address: {}\n", wallet.address())?;
    writeln!(screen, "Wallet mnemonic phrase: {}\n", mnemonic)?;
    screen.flush()?;

    let mut input = String::new();
    println!("### Do not share or lose this mnemonic phrase! Press any key to complete. ###");
    std::io::stdin().read_line(&mut input)?;
    Ok(())
}
