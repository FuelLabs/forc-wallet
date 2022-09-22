use crate::utils::{
    create_accounts_file, derive_account_with_index, number_of_derived_accounts, Accounts,
    DEFAULT_WALLETS_VAULT_PATH,
};
use anyhow::{bail, Result};
use fuels::prelude::*;
use std::{io::Write, path::PathBuf};
use termion::screen::AlternateScreen;

pub(crate) fn print_account(
    path: Option<String>,
    account_index: usize,
    export: bool,
) -> Result<()> {
    let wallet_path = match &path {
        Some(path) => PathBuf::from(path),
        None => home::home_dir().unwrap().join(DEFAULT_WALLETS_VAULT_PATH),
    };
    if export {
        let secret_key = derive_account_with_index(&wallet_path, account_index)?;
        let mut screen = AlternateScreen::from(std::io::stdout());
        writeln!(
            screen,
            "Secret key for account {}: {}\n",
            account_index, secret_key
        )?;
        screen.flush()?;
        let mut input = String::new();
        println!("### Press any key to complete. ###");
        std::io::stdin().read_line(&mut input)?;
    } else {
        let existing_accounts = Accounts::from_dir(&wallet_path)?;
        if let Some(account) = existing_accounts.addresses().iter().nth(account_index) {
            println!("Account {} address: {}", account_index, account);
        } else {
            eprintln!("Account {} is not derived yet!", account_index);
        }
    }
    Ok(())
}

pub(crate) fn new_account(path: Option<String>) -> Result<()> {
    let wallet_path = match &path {
        Some(path) => PathBuf::from(path),
        None => home::home_dir().unwrap().join(DEFAULT_WALLETS_VAULT_PATH),
    };
    let existing_accounts = Accounts::from_dir(&wallet_path)?;
    if !wallet_path.join(".wallet").exists() {
        bail!("Wallet is not initialized, please initialize a wallet before creating an account! To initialize a wallet: \"forc-wallet init\"");
    }
    let account_index = number_of_derived_accounts(&wallet_path);
    println!("Generating account with index: {}", account_index);
    let derive_path = format!("m/44'/1179993420'/{}'/0/0", account_index);
    let password = rpassword::prompt_password(
        "Please enter your password to decrypt initialized wallet's phrases: ",
    )?;
    let phrase_recovered = eth_keystore::decrypt_key(wallet_path.join(".wallet"), password)?;
    let phrase = String::from_utf8(phrase_recovered)?;
    let wallet = WalletUnlocked::new_from_mnemonic_phrase_with_path(&phrase, None, &derive_path)?;

    let mut account_addresses = Vec::from(existing_accounts.addresses());
    account_addresses.push(wallet.address().to_string());
    create_accounts_file(&wallet_path, account_addresses)?;

    println!("Wallet address: {}", wallet.address());
    Ok(())
}
