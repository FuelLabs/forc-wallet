use crate::utils::parse_wallet_path;
use crate::Error;
use std::collections::HashMap;

/// Walks through the wallets vault directory and returns the next index based on the number of
/// wallets in the vault.
pub(crate) fn get_next_wallet_index(dir: &str) -> Result<usize, Error> {
    let sorted_wallets = get_wallets_list(dir)?;
    Ok(sorted_wallets.last().unwrap().0 + 1)
}

/// Walks through the wallets vault directory `dir` and returns a Vec of the wallets as an
/// `(index,address)` tuple.
pub(crate) fn get_wallets_list(dir: &str) -> Result<Vec<(usize, String)>, Error> {
    let mut path = home::home_dir().unwrap();
    path.push(dir);

    // list directories in the path
    let dirs = match std::fs::read_dir(path.clone()) {
        Ok(dirs) => dirs,
        Err(_) => {
            return Err(Error::WalletError(format!(
                "Could not read directory {:?}",
                path
            )));
        }
    };

    let mut wallets = HashMap::new();

    for dir in dirs {
        let dir = dir.unwrap();
        let path = dir.path();

        if path.is_dir() {
            let (index, address) = parse_wallet_path(path)?;
            let s = format!("[{}].         0x{}", index, address);
            wallets.insert(index, s);
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
