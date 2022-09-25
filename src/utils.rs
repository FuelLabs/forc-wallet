use crate::Error;
use anyhow::{anyhow, Result};
use fuel_crypto::SecretKey;
use fuels_signers::wallet::DEFAULT_DERIVATION_PATH_PREFIX;
use home::home_dir;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::{fs, path::Path};
use termion::screen::AlternateScreen;

pub(crate) const DEFAULT_RELATIVE_VAULT_PATH: &str = ".fuel/wallets/";

#[derive(Serialize, Deserialize)]
pub(crate) struct Accounts {
    addresses: Vec<String>,
}

impl Accounts {
    pub(crate) fn new(addresses: Vec<String>) -> Accounts {
        Accounts { addresses }
    }

    pub(crate) fn from_dir(path: &Path) -> Result<Accounts> {
        let accounts_file_path = path.join(".accounts");
        if !accounts_file_path.exists() {
            Ok(Accounts { addresses: vec![] })
        } else {
            let account_file = fs::read_to_string(path.join(".accounts"))?;
            let accounts = serde_json::from_str(&account_file)
                .map_err(|e| anyhow!("failed to parse .accounts: {}.", e))?;
            Ok(accounts)
        }
    }

    pub(crate) fn addresses(&self) -> &[String] {
        &self.addresses
    }
}

/// Create the `.accounts` file which holds the addresses of accounts derived so far
pub(crate) fn create_accounts_file(path: &Path, accounts: Vec<String>) -> Result<()> {
    let account_file = serde_json::to_string(&Accounts::new(accounts))?;
    fs::write(path.join(".accounts"), account_file)?;
    Ok(())
}

/// Returns the number of the accounts derived so far by reading the .accounts file from given path
pub(crate) fn number_of_derived_accounts(path: &Path) -> usize {
    let accounts = Accounts::from_dir(path);
    if let Ok(accounts) = accounts {
        accounts.addresses().len()
    } else {
        0
    }
}

pub(crate) fn derive_account_with_index(path: &Path, account_index: usize) -> Result<SecretKey> {
    let password = rpassword::prompt_password(
        "Please enter your password to decrypt initialized wallet's phrases: ",
    )?;
    let phrase_recovered = eth_keystore::decrypt_key(path.join(".wallet"), password)?;
    let phrase = String::from_utf8(phrase_recovered)?;
    let derive_path = format!("{}/{}'/0/0", DEFAULT_DERIVATION_PATH_PREFIX, account_index);
    let secret_key = SecretKey::new_from_mnemonic_phrase_with_path(&phrase, &derive_path)?;
    Ok(secret_key)
}

pub(crate) fn wait_for_keypress() {
    let mut single_key = [0u8];
    std::io::stdin().read_exact(&mut single_key).unwrap();
}

pub(crate) fn request_new_password() -> String {
    let password =
        rpassword::prompt_password("Please enter a password to encrypt this private key: ")
            .unwrap();

    let confirmation = rpassword::prompt_password("Please confirm your password: ").unwrap();

    if password != confirmation {
        println!("Passwords do not match -- try again!");
        std::process::exit(1);
    }
    password
}

/// Print a string to an alternate screen, so the string isn't printed to the terminal.
pub(crate) fn display_string_discreetly(discreet_string: String) -> Result<(), Error> {
    let mut screen = AlternateScreen::from(std::io::stdout());
    writeln!(screen, "{}", discreet_string)?;
    Ok(screen.flush()?)
}

/// Handle the default path argument and return the right path, error out if the path is not
/// relative to the home directory.
pub(crate) fn handle_vault_path_argument(path: Option<String>) -> Result<PathBuf, Error> {
    let vault_path = match path {
        Some(path) => PathBuf::from(path),
        None => {
            let mut default_relative = home_dir().unwrap();
            default_relative.push(DEFAULT_RELATIVE_VAULT_PATH);
            default_relative
        }
    };
    // If the path is not relative to the home directory, error out.
    // This should never happen if the `path` argument was `None`.
    if !vault_path.starts_with(home_dir().unwrap()) {
        return Err(Error::WalletError(format!(
            "Please provide a path relative to the home directory! Provided path: {:?}",
            vault_path
        )));
    }
    Ok(vault_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_none_argument() -> Result<()> {
        let mut default_relative = home_dir().unwrap();
        default_relative.push(DEFAULT_RELATIVE_VAULT_PATH);
        assert_eq!(default_relative, handle_vault_path_argument(None)?);
        Ok(())
    }

    #[test]
    fn handle_relative_path_argument() -> Result<()> {
        let mut some_relative = home_dir().unwrap();
        some_relative.push("bimbamboum");
        let some_argument = Some(some_relative.display().to_string());
        assert_eq!(some_relative, handle_vault_path_argument(some_argument)?);
        Ok(())
    }

    #[test]
    fn handle_absolute_path_argument() {
        let absolute_path = "/bimbamboum".to_string();
        let result = handle_vault_path_argument(Some(absolute_path));
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Please provide a path relative to the home directory!"));
    }
}
