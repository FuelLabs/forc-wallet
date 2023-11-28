use crate::utils::{
    display_string_discreetly, request_new_password, write_wallet_from_mnemonic_and_password,
};
use fuels::prelude::*;
use std::{
    fs,
    io::stdin,
    path::Path, 
};
use clap::Args;
use forc_tracing::{println_warning, println_red_err};

#[derive(Debug, Args)]
pub struct New {
    /// Set true to automatically replace the existing wallet
    #[clap(short, long)]
    force: bool,
}

pub fn new_wallet_cli(wallet_path: &Path, new: New) -> anyhow::Result<()> {
    if wallet_path.exists() {
        if new.force {
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
                    &format!("Failed to create a new wallet at {} \
                    because a wallet already exists at that location.", 
                    wallet_path.display(),
                ));
                return Ok(());
            }
        }
    }

    let password = request_new_password();
    // Generate a random mnemonic phrase.
    let mnemonic = generate_mnemonic_phrase(&mut rand::thread_rng(), 24)?;
    write_wallet_from_mnemonic_and_password(wallet_path, &mnemonic, &password)?;
    let mnemonic_string = format!("Wallet mnemonic phrase: {mnemonic}\n");
    display_string_discreetly(
        &mnemonic_string,
        "### Do not share or lose this mnemonic phrase! Press any key to complete. ###",
    )?;
    Ok(())
}
