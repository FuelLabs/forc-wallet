use crate::utils::{derived_wallets, DEFAULT_WALLETS_VAULT_PATH};
use crate::Error;
use fuels::prelude::*;
use std::path::{Path, PathBuf};

/// Returns index - public address pair for derived accounts
pub(crate) fn get_wallets_list(path: &Path) -> Result<Vec<(usize, String)>, Error> {
    let wallets = derived_wallets(path)?
        .iter()
        .enumerate()
        .map(|(index, wallet)| (index, wallet.address().to_string()))
        .collect();
    Ok(wallets)
}

pub(crate) fn print_wallet_list(path: Option<String>) -> Result<(), Error> {
    let wallet_path = match &path {
        Some(path) => PathBuf::from(path),
        None => home::home_dir().unwrap().join(DEFAULT_WALLETS_VAULT_PATH),
    };
    let wallets = get_wallets_list(&wallet_path)?;
    println!("#   address\n");
    for wallet in wallets {
        let (index, address) = wallet;
        println!("[{}] {}", index, address);
    }
    Ok(())
}
