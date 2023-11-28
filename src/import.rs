use crate::utils::{request_new_password, write_wallet_from_mnemonic_and_password};
use anyhow::{bail, Result};
use fuels::accounts::wallet::WalletUnlocked;
use std::{
    fs,
    io::stdin,
    path::Path, 
};
use clap::Args;
use forc_tracing::{println_warning, println_red_err};

#[derive(Debug, Args)]
pub struct Import {
    /// Set true to automatically replace the existing wallet
    #[clap(short, long)]
    force: bool,
}

/// Check if given mnemonic is valid by trying to create a `WalletUnlocked` from it
fn check_mnemonic(mnemonic: &str) -> Result<()> {
    // Check users's phrase by trying to create a wallet from it
    if WalletUnlocked::new_from_mnemonic_phrase(mnemonic, None).is_err() {
        bail!("Cannot generate a wallet from provided mnemonics, please check your mnemonic phrase")
    }
    Ok(())
}

pub fn import_wallet_cli(wallet_path: &Path, import: Import) -> Result<()> {
    if wallet_path.exists() {
        if import.force {
            fs::remove_file(wallet_path)?;
        } else {
            println_warning(
                &format!("There is an existing wallet at {}. \
                Do you wish to replace it with a new wallet? (y/N) ", 
                wallet_path.display(),
            ));
            let mut need_replace = String::new();
            stdin().read_line(&mut need_replace)?;
            if need_replace.trim() == "y" {
                fs::remove_file(wallet_path)?;
            } else {
                println_red_err(
                    &format!("Failed to import a new wallet at {} \
                    because a wallet already exists at that location.", 
                    wallet_path.display(),
                ));
                return Ok(());
            }
        }
    }

    let mnemonic = rpassword::prompt_password("Please enter your mnemonic phrase: ")?;
    check_mnemonic(&mnemonic)?;
    let password = request_new_password();
    write_wallet_from_mnemonic_and_password(wallet_path, &mnemonic, &password)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::TEST_MNEMONIC;

    #[test]
    fn check_mnemonic_should_succeed() {
        assert!(check_mnemonic(TEST_MNEMONIC).is_ok())
    }

    #[test]
    fn check_mnemonic_should_fail() {
        let invalid_mnemonic = "this is an invalid mnemonic";
        assert!(check_mnemonic(invalid_mnemonic).is_err())
    }
}
