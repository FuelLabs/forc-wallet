use crate::utils::{handle_vault_path_argument, Accounts};
use crate::Error;
use std::path::Path;

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
    let vault_path = handle_vault_path_argument(path)?;
    if !vault_path.exists() {
        return Err(Error::WalletError(format!(
            "No wallets found at path {:?}",
            vault_path
        )));
    }
    let wallets = get_wallets_list(&vault_path)?;
    println!("#   address\n");
    for wallet in wallets {
        let (index, address) = wallet;
        println!("[{}] {}", index, address);
    }
    Ok(())
}
