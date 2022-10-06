use crate::utils::{
    create_accounts_file, get_derivation_path, handle_vault_path, number_of_derived_accounts,
    Accounts,
};
use anyhow::{bail, Result};
use fuels::prelude::WalletUnlocked;
use std::path::PathBuf;

pub(crate) fn print_account_address(path: Option<String>, account_index: usize) -> Result<()> {
    let vault_path = handle_vault_path(false, path)?;
    let existing_accounts = Accounts::from_dir(vault_path)?;
    if let Some(account) = existing_accounts.addresses().iter().nth(account_index) {
        println!("Account {} address: {}", account_index, account);
    } else {
        eprintln!("Account {} is not derived yet!", account_index);
    }
    Ok(())
}

fn new_account<P>(vault_path: P, password: &str) -> Result<WalletUnlocked>
where
    P: Into<PathBuf>,
{
    let vault_path_buf = vault_path.into();
    let account_index = number_of_derived_accounts(&vault_path_buf);
    println!("Generating account with index: {}", account_index);
    let derive_path = get_derivation_path(account_index);

    let phrase_recovered = eth_keystore::decrypt_key(vault_path_buf.join(".wallet"), password)?;
    let phrase = String::from_utf8(phrase_recovered)?;
    let wallet = WalletUnlocked::new_from_mnemonic_phrase_with_path(&phrase, None, &derive_path)?;
    Ok(wallet)
}

pub(crate) fn new_account_cli(path: Option<String>) -> Result<()> {
    let vault_path = handle_vault_path(false, path)?;
    let existing_accounts = Accounts::from_dir(vault_path.clone())?;
    if !vault_path.join(".wallet").exists() {
        bail!("Wallet is not initialized, please initialize a wallet before creating an account! To initialize a wallet: \"forc-wallet init\"");
    }
    let password = rpassword::prompt_password(
        "Please enter your password to decrypt initialized wallet's phrases: ",
    )?;

    let wallet = new_account(&vault_path, &password)?;

    let mut account_addresses = Vec::from(existing_accounts.addresses());
    account_addresses.push(wallet.address().to_string());
    create_accounts_file(&vault_path, account_addresses)?;

    println!("Wallet address: {}", wallet.address());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{save_dummy_wallet_file, with_tmp_folder, TEST_PASSWORD};
    use serial_test::serial;

    #[test]
    #[serial]
    fn create_new_account() {
        with_tmp_folder(|tmp_folder| {
            // init test wallet
            save_dummy_wallet_file(tmp_folder);
            let account_is_ok = new_account(tmp_folder, TEST_PASSWORD).is_ok();
            assert!(account_is_ok)
        });
    }
}
