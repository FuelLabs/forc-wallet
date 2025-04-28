use crate::utils::display_string_discreetly;
use anyhow::{Context, Result, anyhow};
use rpassword::prompt_password;
use std::path::Path;

/// Decrypts a wallet using provided password
fn decrypt_wallet(wallet_path: &Path, password: &str) -> Result<String> {
    let phrase_bytes = eth_keystore::decrypt_key(wallet_path, password)
        .map_err(|e| anyhow!("Failed to decrypt keystore: {}", e))?;

    String::from_utf8(phrase_bytes).context("Invalid UTF-8 in mnemonic phrase")
}

/// Prints the wallet at the given path as mnemonic phrase as a discrete string
pub fn export_wallet_cli(wallet_path: &Path) -> Result<()> {
    let prompt = "Please enter your wallet password to export your wallet: ";
    let password = prompt_password(prompt)?;
    let phrase = decrypt_wallet(wallet_path, &password)?;

    // Display phrase in alternate screen
    display_string_discreetly(
        &phrase,
        "### Do not share or lose this mnemonic phrase! Press any key to complete. ###",
    )?;

    Ok(())
}
