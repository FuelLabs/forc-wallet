use crate::utils::display_string_discreetly;
use anyhow::{Context, Result, anyhow};
use rpassword::prompt_password;
use std::path::Path;

/// Decrypts a wallet using provided password
fn decrypt_mnemonic(wallet_path: &Path, password: &str) -> Result<String> {
    let phrase_bytes = eth_keystore::decrypt_key(wallet_path, password)
        .map_err(|e| anyhow!("Failed to decrypt keystore: {}", e))?;

    String::from_utf8(phrase_bytes).context("Invalid UTF-8 in mnemonic phrase")
}

/// Prints the wallet at the given path as mnemonic phrase as a discrete string
pub fn export_wallet_cli(wallet_path: &Path) -> Result<()> {
    let prompt = "Please enter your wallet password to export your wallet: ";
    let password = prompt_password(prompt)?;
    let phrase = decrypt_mnemonic(wallet_path, &password)?;

    // Display phrase in alternate screen
    display_string_discreetly(
        &phrase,
        "### Do not share or lose this mnemonic phrase! Press any key to complete. ###",
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        export::decrypt_mnemonic,
        utils::test_utils::{TEST_MNEMONIC, TEST_PASSWORD, with_tmp_dir_and_wallet},
    };

    #[test]
    fn decrypt_wallet() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            let decrypted_mnemonic = decrypt_mnemonic(wallet_path, TEST_PASSWORD).unwrap();
            assert_eq!(decrypted_mnemonic, TEST_MNEMONIC)
        });
    }
}
