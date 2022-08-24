use std::{io::Write, path::PathBuf};

use anyhow::Result;
use fuels::signers::wallet::Wallet;
use termion::screen::AlternateScreen;

use crate::utils::{
    clear_wallets_vault, request_new_password, wait_for_keypress, DEFAULT_WALLETS_VAULT_PATH,
};

pub(crate) fn init_wallet(path: Option<String>) -> Result<()> {
    let wallet_path = match &path {
        Some(path) => {
            // If the provided path exists but used clear it
            clear_wallets_vault(&PathBuf::from(&path))?;
            // If the provided path does not exists create it
            std::fs::create_dir_all(path)?;
            PathBuf::from(path)
        }
        None => {
            let mut path = home::home_dir().unwrap();
            path.push(DEFAULT_WALLETS_VAULT_PATH);
            // If the default vault path exists but is used clear it
            clear_wallets_vault(&path)?;
            // If the default vault path does not exists create it
            std::fs::create_dir_all(&path)?;
            path
        }
    };
    // Generate mnemonic phrase
    let mnemonic = Wallet::generate_mnemonic_phrase(&mut rand::thread_rng(), 24)?;
    // Encrypt and store it
    let mnemonic_bytes: Vec<u8> = mnemonic.bytes().collect();
    let password = request_new_password();

    eth_keystore::encrypt_key(
        &wallet_path,
        &mut rand::thread_rng(),
        mnemonic_bytes,
        &password,
        Some(".wallet"),
    )?;
    // Print to an alternate screen, so the mnemonic phrase isn't printed to the terminal.
    let mut screen = AlternateScreen::from(std::io::stdout());
    writeln!(screen, "Wallet mnemonic phrase: {}\n", mnemonic)?;
    screen.flush()?;
    println!("### Do not share or lose this mnemonic phrase! Press any key to complete. ###");
    wait_for_keypress();
    Ok(())
}
