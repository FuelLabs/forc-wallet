use crate::utils::{Accounts, DEFAULT_WALLETS_VAULT_PATH};
use crate::Error;
use std::path::{Path, PathBuf};

/// Returns index - public address pair for derived accounts
pub(crate) fn get_wallets_list(path: &Path) -> Result<Vec<(usize, String)>, Error> {
    let wallets = Accounts::from_dir(path)?
        .addresses()
        .iter()
        .enumerate()
        .map(|(index, address)| (index, address.clone()))
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
