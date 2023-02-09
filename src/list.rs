use crate::utils::{default_vault_path, validate_vault_path, Accounts};
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

/// Returns index - public address pair for derived accounts
pub(crate) fn get_wallets_list(path: &Path) -> Result<Vec<(usize, String)>> {
    let wallets = Accounts::from_dir(path)?
        .addresses()
        .iter()
        .enumerate()
        .map(|(index, address)| (index, address.clone()))
        .collect();
    Ok(wallets)
}

pub(crate) fn print_wallet_list(path_opt: Option<PathBuf>) -> Result<()> {
    let path = path_opt.unwrap_or_else(default_vault_path);
    validate_vault_path(&path)?;
    if !path.exists() {
        bail!("No wallets found in {:?}", path);
    }
    let wallets = get_wallets_list(&path)?;
    println!("#   address\n");
    for wallet in wallets {
        let (index, address) = wallet;
        println!("[{index}] {address}");
    }
    Ok(())
}
