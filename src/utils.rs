use anyhow::{anyhow, bail, Context, Ok, Result};
use eth_keystore::EthKeystore;
use forc_tracing::println_warning;
use fuels::accounts::wallet::DEFAULT_DERIVATION_PATH_PREFIX;
use home::home_dir;
use std::{
    fs,
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
};

/// The user's fuel directory (stores state related to fuel-core, wallet, etc).
pub fn user_fuel_dir() -> PathBuf {
    const USER_FUEL_DIR: &str = ".fuel";
    let home_dir = home_dir().expect("failed to retrieve user home directory");
    home_dir.join(USER_FUEL_DIR)
}

/// The directory under which `forc wallet` generates wallets.
pub fn user_fuel_wallets_dir() -> PathBuf {
    const WALLETS_DIR: &str = "wallets";
    user_fuel_dir().join(WALLETS_DIR)
}

/// The directory used to cache wallet account addresses.
pub fn user_fuel_wallets_accounts_dir() -> PathBuf {
    const ACCOUNTS_DIR: &str = "accounts";
    user_fuel_wallets_dir().join(ACCOUNTS_DIR)
}

/// Returns default wallet path which is `$HOME/.fuel/wallets/.wallet`.
pub fn default_wallet_path() -> PathBuf {
    const DEFAULT_WALLET_FILE_NAME: &str = ".wallet";
    user_fuel_wallets_dir().join(DEFAULT_WALLET_FILE_NAME)
}

/// Load a wallet from the given path.
pub fn load_wallet(wallet_path: &Path) -> Result<EthKeystore> {
    let file = fs::File::open(wallet_path).map_err(|e| {
        anyhow!(
            "Failed to load a wallet from {wallet_path:?}: {e}.\n\
            Please be sure to initialize a wallet before creating an account.\n\
            To initialize a wallet, use `forc-wallet new`"
        )
    })?;
    let reader = std::io::BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| {
        anyhow!(
            "Failed to deserialize keystore from {wallet_path:?}: {e}.\n\
            Please ensure that {wallet_path:?} is a valid wallet file."
        )
    })
}

pub(crate) fn wait_for_keypress() {
    let mut single_key = [0u8];
    std::io::stdin().read_exact(&mut single_key).unwrap();
}

/// Returns the derivation path with account index using the default derivation path from SDK
pub(crate) fn get_derivation_path(account_index: usize) -> String {
    format!("{DEFAULT_DERIVATION_PATH_PREFIX}/{account_index}'/0/0")
}

pub(crate) fn request_new_password() -> String {
    let password =
        rpassword::prompt_password("Please enter a password to encrypt this private key: ")
            .unwrap();

    let confirmation = rpassword::prompt_password("Please confirm your password: ").unwrap();

    if password != confirmation {
        println!("Passwords do not match -- try again!");
        std::process::exit(1);
    }
    password
}

/// Print a string to an alternate screen, so the string isn't printed to the terminal.
pub(crate) fn display_string_discreetly(
    discreet_string: &str,
    continue_message: &str,
) -> Result<()> {
    use termion::screen::IntoAlternateScreen;
    let mut screen = std::io::stdout().into_alternate_screen()?;
    writeln!(screen, "{discreet_string}")?;
    screen.flush()?;
    println!("{continue_message}");
    wait_for_keypress();
    Ok(())
}

/// Encrypts the given mnemonic with the given password and writes it to a file at the given path.
///
/// Ensures that the parent dir exists, but that we're not directly overwriting an existing file.
///
/// The resulting wallet file will be a keystore as per the [Web3 Secret Storage Definition][1].
/// [1]: https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage.
pub(crate) fn write_wallet_from_mnemonic_and_password(
    wallet_path: &Path,
    mnemonic: &str,
    password: &str,
) -> Result<()> {
    // Ensure we're not overwriting an existing wallet or other file.
    // As we have check the wallet path above, there should be no existing wallet.
    // In case it exists(as there is an interactive inputting password or inputting mnemonic phrase flow above,
    // there maybe another processes come here), return error
    if wallet_path.exists() {
        bail!(
            "File or directory already exists at {wallet_path:?}. \
            Remove the existing file, or provide a different path."
        );
    }

    // Ensure the parent directory exists.
    let wallet_dir = wallet_path
        .parent()
        .ok_or_else(|| anyhow!("failed to retrieve parent directory of {wallet_path:?}"))?;
    std::fs::create_dir_all(wallet_dir)?;

    // Retrieve the wallet file name.
    let wallet_file_name = wallet_path
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .ok_or_else(|| anyhow!("failed to retrieve file name from {wallet_path:?}"))?;

    // Encrypt and write the wallet file.
    eth_keystore::encrypt_key(
        wallet_dir,
        &mut rand::thread_rng(),
        mnemonic,
        password,
        Some(wallet_file_name),
    )
    .with_context(|| format!("failed to create keystore at {wallet_path:?}"))
    .map(|_| ())
}

/// Ensures there is no wallet at the given [Path], removing an existing wallet if the user has
/// provided the `--force` option or chooses to remove it in the CLI interaction.
/// Returns [Err] if there is an existing wallet and the user chooses not to remove it.
pub(crate) fn ensure_no_wallet_exists(
    wallet_path: &Path,
    force: bool,
    mut reader: impl BufRead,
) -> Result<()> {
    if wallet_path.exists() {
        if force {
            println_warning(&format!(
                "Because the `--force` argument was supplied, the wallet at {} will be removed.",
                wallet_path.display(),
            ));
            fs::remove_file(wallet_path).unwrap();
        } else {
            println_warning(&format!(
                "There is an existing wallet at {}. \
                Do you wish to replace it with a new wallet? (y/N) ",
                wallet_path.display(),
            ));
            let mut need_replace = String::new();
            reader.read_line(&mut need_replace).unwrap();
            if need_replace.trim() == "y" {
                fs::remove_file(wallet_path).unwrap();
            } else {
                bail!(
                    "Failed to create a new wallet at {} \
                    because a wallet already exists at that location.",
                    wallet_path.display(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{with_tmp_dir, TEST_MNEMONIC, TEST_PASSWORD};
    // simulate input
    const INPUT_NOP: &[u8; 1] = b"\n";
    const INPUT_YES: &[u8; 2] = b"y\n";
    const INPUT_NO: &[u8; 2] = b"n\n";

    fn remove_wallet(wallet_path: &Path) {
        if wallet_path.exists() {
            fs::remove_file(wallet_path).unwrap();
        }
    }
    fn create_wallet(wallet_path: &Path) {
        if !wallet_path.exists() {
            fs::File::create(wallet_path).unwrap();
        }
    }

    #[test]
    fn handle_absolute_path_argument() {
        with_tmp_dir(|tmp_dir| {
            let tmp_dir_abs = tmp_dir.canonicalize().unwrap();
            let wallet_path = tmp_dir_abs.join("wallet.json");
            write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
                .unwrap();
            load_wallet(&wallet_path).unwrap();
        })
    }

    #[test]
    fn handle_relative_path_argument() {
        let wallet_path = Path::new("test-wallet.json");
        let panic = std::panic::catch_unwind(|| {
            write_wallet_from_mnemonic_and_password(wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
                .unwrap();
            load_wallet(wallet_path).unwrap();
        });
        let _ = std::fs::remove_file(wallet_path);
        if let Err(e) = panic {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn derivation_path() {
        let derivation_path = get_derivation_path(0);
        assert_eq!(derivation_path, "m/44'/1179993420'/0'/0/0");
    }
    #[test]
    fn encrypt_and_save_phrase() {
        with_tmp_dir(|tmp_dir| {
            let wallet_path = tmp_dir.join("wallet.json");
            write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
                .unwrap();
            let phrase_recovered = eth_keystore::decrypt_key(wallet_path, TEST_PASSWORD).unwrap();
            let phrase = String::from_utf8(phrase_recovered).unwrap();
            assert_eq!(phrase, TEST_MNEMONIC)
        });
    }

    #[test]
    fn write_wallet() {
        with_tmp_dir(|tmp_dir| {
            let wallet_path = tmp_dir.join("wallet.json");
            write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
                .unwrap();
            load_wallet(&wallet_path).unwrap();
        })
    }

    #[test]
    #[should_panic]
    fn write_wallet_to_existing_file_should_fail() {
        with_tmp_dir(|tmp_dir| {
            let wallet_path = tmp_dir.join("wallet.json");
            write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
                .unwrap();
            write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
                .unwrap();
        })
    }

    #[test]
    fn write_wallet_subdir() {
        with_tmp_dir(|tmp_dir| {
            let wallet_path = tmp_dir.join("path").join("to").join("wallet");
            write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
                .unwrap();
            load_wallet(&wallet_path).unwrap();
        })
    }

    #[test]
    // case: wallet path not exist
    fn test_ensure_no_wallet_exists_no_wallet() {
        with_tmp_dir(|tmp_dir| {
            let wallet_path = tmp_dir.join("wallet.json");
            remove_wallet(&wallet_path);
            ensure_no_wallet_exists(&wallet_path, false, &INPUT_NOP[..]).unwrap();
        });
    }

    #[test]
    #[should_panic]
    // case: wallet path exist without --force and input[no]
    fn test_ensure_no_wallet_exists_throws_err() {
        with_tmp_dir(|tmp_dir| {
            let wallet_path = tmp_dir.join("wallet.json");
            create_wallet(&wallet_path);
            ensure_no_wallet_exists(&wallet_path, false, &INPUT_NO[..]).unwrap();
        });
    }

    #[test]
    // case: wallet path exist
    fn test_ensure_no_wallet_exists_exists_wallet() {
        // case: wallet path exist without --force and input[yes]
        with_tmp_dir(|tmp_dir| {
            let wallet_path = tmp_dir.join("wallet.json");
            create_wallet(&wallet_path);
            ensure_no_wallet_exists(&wallet_path, false, &INPUT_YES[..]).unwrap();
        });
        // case: wallet path exist with --force
        with_tmp_dir(|tmp_dir| {
            let wallet_path = tmp_dir.join("wallet.json");
            create_wallet(&wallet_path);
            ensure_no_wallet_exists(&wallet_path, true, &INPUT_NOP[..]).unwrap();
        });
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use std::{panic, path::Path};

    pub(crate) const TEST_MNEMONIC: &str = "rapid mechanic escape victory bacon switch soda math embrace frozen novel document wait motor thrive ski addict ripple bid magnet horse merge brisk exile";
    pub(crate) const TEST_PASSWORD: &str = "1234";

    /// Create a tmp folder and execute the given test function `f`
    pub(crate) fn with_tmp_dir<F>(f: F)
    where
        F: FnOnce(&Path) + panic::UnwindSafe,
    {
        let tmp_dir_name = format!("forc-wallet-test-{:x}", rand::random::<u64>());
        let tmp_dir = user_fuel_dir().join(".tmp").join(tmp_dir_name);
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let panic = panic::catch_unwind(|| f(&tmp_dir));
        std::fs::remove_dir_all(&tmp_dir).unwrap();
        if let Err(e) = panic {
            panic::resume_unwind(e);
        }
    }

    /// Saves a default test mnemonic to the disk
    pub(crate) fn save_dummy_wallet_file(wallet_path: &Path) {
        write_wallet_from_mnemonic_and_password(wallet_path, TEST_MNEMONIC, TEST_PASSWORD).unwrap();
    }

    /// The same as `with_tmp_dir`, but also provides a test wallet.
    pub(crate) fn with_tmp_dir_and_wallet<F>(f: F)
    where
        F: FnOnce(&Path, &Path) + panic::UnwindSafe,
    {
        with_tmp_dir(|dir| {
            let wallet_path = dir.join("wallet.json");
            save_dummy_wallet_file(&wallet_path);
            f(dir, &wallet_path);
        })
    }
}
