use crate::list::get_wallets_list;
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
    Ok(sorted_wallets.last().unwrap().0 + 1)
}

pub(crate) async fn create_wallet(path: Option<PathBuf>) -> Result<(), Error> {
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

    // TODO: check that the path has the right index??? not rly sure
    // Wallets are created in ~/.fuel/wallets/ following the format below:
    // <index>_<public_address>/<uuid>.
    // The index is the wallet's index in the list of wallets.
    let path = path.unwrap_or_else(|| {
        let mut path = home::home_dir().unwrap();
        path.push(DEFAULT_WALLETS_VAULT_PATH);
        path.push(format!(
            "{}_{}",
            get_next_wallet_index(DEFAULT_WALLETS_VAULT_PATH).unwrap(),
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
    Ok(())
}
