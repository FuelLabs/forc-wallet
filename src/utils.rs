use anyhow::{anyhow, Result};
use fuel_crypto::SecretKey;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::{fs, path::Path};

pub(crate) const DEFAULT_WALLETS_VAULT_PATH: &str = ".fuel/wallets/";

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

pub(crate) fn clear_wallets_vault(path: &Path) -> Result<()> {
    if path.exists() {
        println!("Clearing existing vault\n");
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
    }
    Ok(())
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
    let derive_path = format!("m/44'/1179993420'/{}'/0/0", account_index);
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
