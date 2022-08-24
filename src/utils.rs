use crate::Error;
use anyhow::Result;
use std::{fs, path::PathBuf};

pub(crate) fn parse_wallet_path(filepath: PathBuf) -> Result<(usize, String), Error> {
    // Filename is the last component of the complete filepath
    let wallet_filename = filepath.file_name().unwrap().to_str().unwrap();
    // The filename format for a wallet (which is a directory) is <index>_<public_address>
    let split: Vec<String> = wallet_filename.split('_').map(|s| s.to_string()).collect();
    if split.len() != 2 {
        return Err(Error::InvalidData(format!(
            "Wallet filename `{}` has {} parts, expected 2",
            wallet_filename,
            split.len()
        )));
    }
    let index = split.first().unwrap().parse::<usize>().unwrap();
    let address = split.last().unwrap().clone();
    Ok((index, address))
}

pub(crate) fn clear_wallets_vault(path: &PathBuf) -> Result<()> {
    if path.exists() {
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
