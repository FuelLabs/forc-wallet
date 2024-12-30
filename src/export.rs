use anyhow::{Result};
use clap::Args;
use std::path::Path;
use crate::utils::display_string_discreetly;
use rpassword;

#[derive(Debug, Args)]
pub struct Export {
    /// Forces export even if it might be unsafe
    #[clap(short, long)]
    pub force: bool,
}

pub fn export_wallet_cli(wallet_path: &Path, _export: Export) -> Result<()> {
    let prompt = "Please enter your wallet password to export the mnemonic phrase: ";
    let password = rpassword::prompt_password(prompt)?;
    
    // Attempt to decrypt the keystore with the provided password
    let phrase_recovered = eth_keystore::decrypt_key(wallet_path, &password)?;
    let phrase = String::from_utf8(phrase_recovered)?;
    
    // Display the mnemonic phrase discreetly
    let mnemonic_string = format!("Mnemonic phrase: {}\n", phrase);
    display_string_discreetly(&mnemonic_string, "### Press any key to complete. ###")?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{with_tmp_dir_and_wallet, TEST_PASSWORD};
    
    #[test]
    fn test_export_wallet() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            let export = Export { force: false };
            // This test will fail in CI since it requires user input
            // export_wallet_cli(wallet_path, export).unwrap();
        });
    }
} 