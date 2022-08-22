use crate::utils::parse_wallet_path;
use crate::Error;
use std::collections::HashMap;

/// Walks through the wallets vault directory `dir` and returns a Vec of the wallets as an
/// `(index,address)` tuple.
pub(crate) fn get_wallets_list(dir: &str) -> Result<Vec<(usize, String)>, Error> {
    let path = home::home_dir().unwrap().join(dir);

    // list directories in the path
    let dirs = std::fs::read_dir(&path)
        .map_err(|_| Error::WalletError(format!("Could not read directory {:?}", path)))?;

    let mut wallets = Vec::new();

    for dir in dirs {
        let dir = dir.unwrap();
        let path = dir.path();

        if path.is_dir() {
            let (index, address) = parse_wallet_path(path)?;
            let s = format!("[{}].         0x{}", index, address);
            wallets.push((index, s));
        }
    }

    let mut sorted_wallets = wallets.into_iter().collect::<Vec<_>>();
    sorted_wallets.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(sorted_wallets)
}

pub(crate) fn print_wallet_list(dir: String) -> Result<(), Error> {
    for wallet in get_wallets_list(&dir)? {
        println!("{}", wallet.1);
    }
    Ok(())
}
