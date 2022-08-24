use anyhow::Result;
use fuels::signers::wallet::Wallet;
use std::{fs, path::Path};

pub(crate) const DEFAULT_WALLETS_VAULT_PATH: &str = ".fuel/wallets/";

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

/// Create the `.accounts` file which holds the number of derived accounts so far
pub(crate) fn create_accounts_file(path: &Path, number_of_derived: usize) -> Result<()> {
    fs::write(path.join(".accounts"), number_of_derived.to_string())?;
    Ok(())
}

/// Read the number of accounts from `.accounts` file
pub(crate) fn number_of_derived_accounts(path: &Path) -> Result<usize> {
    let accounts_file_content = fs::read_to_string(path.join(".accounts"));
    if let Ok(accounts_file_content) = accounts_file_content {
        Ok(accounts_file_content.parse()?)
    } else {
        Ok(0)
    }
}

/// Derives the already created accounts
pub(crate) fn derived_wallets(path: &Path) -> Result<Vec<Wallet>> {
    let mut wallets = Vec::new();
    let number_of_previously_derived = number_of_derived_accounts(path)?;
    let password = rpassword::prompt_password(
        "Please enter your password to decrypt initialized wallet's phrases: ",
    )?;
    let phrase_recovered = eth_keystore::decrypt_key(path.join(".wallet"), password)?;
    let phrase = String::from_utf8(phrase_recovered)?;

    for account_index in 0..number_of_previously_derived {
        let derive_path = format!("m/44'/1179993420'/{}'/0/0", account_index);
        let wallet = Wallet::new_from_mnemonic_phrase_with_path(&phrase, None, &derive_path)?;
        wallets.push(wallet);
    }
    Ok(wallets)
}
