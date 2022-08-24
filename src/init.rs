use std::{io::Write, path::PathBuf};

use anyhow::Result;
use fuels::signers::wallet::Wallet;
use termion::screen::AlternateScreen;

use crate::{account::DEFAULT_WALLETS_VAULT_PATH, utils::clear_wallets_vault};

pub(crate) fn init_wallet(path: Option<String>) -> Result<()> {
    let wallet_path = match &path {
        Some(path) => {
            // If the provided path does not exists create it
            std::fs::create_dir_all(path)?;
            // If the provided path exists but used clear it
            clear_wallets_vault(&PathBuf::from(&path))?;
            PathBuf::from(path)
        }
        None => {
            let mut path = home::home_dir().unwrap();
            path.push(DEFAULT_WALLETS_VAULT_PATH);
            // If the default vault path does not exists create it
            std::fs::create_dir_all(&path)?;
            // If the default vault path exists but used clear it
            clear_wallets_vault(&path)?;
            path
        }
    };
    // Generate mnenomic phrase
    let mnemonic = Wallet::generate_mnemonic_phrase(&mut rand::thread_rng(), 12)?;
    // Encyrpt and store it
    let mnemonic_bytes: Vec<u8> = mnemonic.bytes().collect();
    let password = rpassword::prompt_password("Please enter a password to encrypt the phrases: ")?;
    eth_keystore::encrypt_key(
        &wallet_path,
        &mut rand::thread_rng(),
        mnemonic_bytes,
        &password,
        Some(".wallet"),
    )?;
    let mut screen = AlternateScreen::from(std::io::stdout());
    writeln!(screen, "Wallet mnemonic phrase: {}\n", mnemonic)?;
    screen.flush()?;
    let mut input = String::new();
    println!("### Do not share or lose this mnemonic phrase! Press any key to complete. ###");
    std::io::stdin().read_line(&mut input)?;
    Ok(())
}
