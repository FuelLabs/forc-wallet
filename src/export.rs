use anyhow::{Result, Context, anyhow};
use clap::Args;
use std::path::Path;
use crate::{
    account::derive_and_cache_addresses,
    utils::{display_string_discreetly, load_wallet},
    DEFAULT_CACHE_ACCOUNTS,
};

#[derive(Debug, Args)]
pub struct Export {
    /// Forces export even if it might be unsafe
    #[clap(short, long)]
    pub force: bool,
    /// How many accounts to cache by default (Default 10)
    #[clap(short, long)]
    pub cache_accounts: Option<usize>,
}

/// Decrypts a wallet using provided password
fn decrypt_wallet(wallet_path: &Path, password: &str) -> Result<String> {
    let phrase_bytes = eth_keystore::decrypt_key(wallet_path, password)
        .map_err(|e| anyhow!("Failed to decrypt keystore: {}", e))?;
    
    String::from_utf8(phrase_bytes)
        .context("Invalid UTF-8 in mnemonic phrase")
}

/// Prompts for password securely
fn prompt_password() -> Result<String> {
    const PROMPT: &str = "Please enter your wallet password to export the mnemonic phrase: ";
    rpassword::prompt_password(PROMPT)
        .map_err(|e| anyhow!("Password prompt error: {}", e))
}

/// Displays mnemonic in alternate screen
fn display_mnemonic(phrase: &str) -> Result<()> {
    let mnemonic_string = format!("Mnemonic phrase: {}\n", phrase);
    display_string_discreetly(&mnemonic_string, "### Press any key to complete. ###")
}

/// Securely wipes sensitive data from memory
fn secure_wipe(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }
}

pub fn export_wallet_cli(wallet_path: &Path, export: Export) -> Result<()> {
    let password = prompt_password()?;
    let phrase = export_wallet(wallet_path, &password)?;

    // Display phrase in alternate screen
    display_mnemonic(&phrase)
        .context("Failed to display mnemonic")?;

    let wallet = load_wallet(wallet_path)?;

    // After user exits alternate screen, derive and cache addresses
    derive_and_cache_addresses(
        &wallet,
        &phrase,
        0..export.cache_accounts.unwrap_or(DEFAULT_CACHE_ACCOUNTS),
    ).context("Failed to derive and cache addresses")?;

    secure_wipe(&mut phrase.into_bytes());
    Ok(())
}

fn export_wallet(wallet_path: &Path, password: &str) -> Result<String> {
    let phrase = decrypt_wallet(wallet_path, password)
        .context("Failed to decrypt wallet")?;
    
    Ok(phrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{with_tmp_dir_and_wallet, TEST_PASSWORD};

    #[test]
    fn test_decrypt_wallet() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            let result = decrypt_wallet(&wallet_path, TEST_PASSWORD);
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_decrypt_wallet_wrong_password() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            let result = decrypt_wallet(&wallet_path, "wrong_password");
            assert!(result.is_err());
        });
    }

    #[test]
    fn test_export_wallet() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            let result = export_wallet(&wallet_path, TEST_PASSWORD);
            assert!(result.is_ok());

            if let Ok(phrase) = result {
                assert!(!phrase.is_empty());
            }
        });
    }

    #[test]
    fn test_display_mnemonic() {
        let result = display_mnemonic("test phrase");
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_wipe() {
        let mut sensitive_data = vec![1u8, 2, 3, 4, 5];
        secure_wipe(&mut sensitive_data);
        assert!(sensitive_data.iter().all(|&byte| byte == 0));
    }
}