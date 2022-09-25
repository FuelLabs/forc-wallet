use crate::utils::{
    create_accounts_file, handle_vault_path_argument, number_of_derived_accounts, Accounts,
};
use anyhow::{bail, Result};
use fuels::prelude::*;

pub(crate) fn print_account_address(path: Option<String>, account_index: usize) -> Result<()> {
    let vault_path = handle_vault_path_argument(path)?;
    let existing_accounts = Accounts::from_dir(&vault_path)?;
    if let Some(account) = existing_accounts.addresses().iter().nth(account_index) {
        println!("Account {} address: {}", account_index, account);
    } else {
        eprintln!("Account {} is not derived yet!", account_index);
    }
    Ok(())
}

pub(crate) fn new_account(path: Option<String>) -> Result<()> {
    let vault_path = handle_vault_path_argument(path)?;
    let existing_accounts = Accounts::from_dir(&vault_path)?;
    if !vault_path.join(".wallet").exists() {
        bail!("Wallet is not initialized, please initialize a wallet before creating an account! To initialize a wallet: \"forc-wallet init\"");
    }
    let account_index = number_of_derived_accounts(&vault_path);
    println!("Generating account with index: {}", account_index);
    let derive_path = format!("m/44'/1179993420'/{}'/0/0", account_index);
    let password = rpassword::prompt_password(
        "Please enter your password to decrypt initialized wallet's phrases: ",
    )?;
    let phrase_recovered = eth_keystore::decrypt_key(vault_path.join(".wallet"), password)?;
    let phrase = String::from_utf8(phrase_recovered)?;
    let wallet = WalletUnlocked::new_from_mnemonic_phrase_with_path(&phrase, None, &derive_path)?;

    let mut account_addresses = Vec::from(existing_accounts.addresses());
    account_addresses.push(wallet.address().to_string());
    create_accounts_file(&vault_path, account_addresses)?;

    println!("Wallet address: {}", wallet.address());
    Ok(())
}
