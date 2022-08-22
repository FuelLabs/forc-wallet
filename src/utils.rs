use crate::Error;
use std::path::PathBuf;

pub(crate) fn parse_wallet_path(filepath: PathBuf) -> Result<(usize, String), Error> {
    // Filename is the last component of the complete filepath
    let wallet_filename = filepath
        .components()
        .last()
        .unwrap()
        .as_os_str()
        .to_str()
        .unwrap();
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
