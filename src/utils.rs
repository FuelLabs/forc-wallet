use crate::Error;
use anyhow::{anyhow, bail, Context, Result};
use eth_keystore::EthKeystore;
use fuel_crypto::SecretKey;
use fuels_signers::wallet::DEFAULT_DERIVATION_PATH_PREFIX;
use home::home_dir;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use termion::screen::AlternateScreen;

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

/// Ensure that the given wallet path points to a file and not a directory.
pub fn validate_wallet_path(wallet_path: &Path) -> Result<()> {
    if !wallet_path.is_file() {
        bail!(
            "expected a path to a wallet keystore file, found {:?}",
            wallet_path
        );
    }
    Ok(())
}

/// Load a wallet from the given path.
pub fn load_wallet(wallet_path: &Path) -> Result<EthKeystore> {
    let file = fs::File::open(&wallet_path).context("failed to open wallet file")?;
    let reader = std::io::BufReader::new(file);
    serde_json::from_reader(reader)
        .with_context(|| format!("failed to deserialize keystore from {wallet_path:?}"))
}

/// Creates the wallet directory at the given path if it does not exist.
pub(crate) fn create_wallet(path: &Path) -> Result<()> {
    if path.exists() {
        bail!(format!("Cannot import wallet at {path:?}, the directory already exists! You can clear the given path and re-use the same path"))
    } else {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Given a path to a wallet, an account index and the wallet's password,
/// derive the account address for the account at the given index.
pub(crate) fn derive_account(
    wallet_path: &Path,
    account_index: usize,
    password: &str,
) -> Result<SecretKey> {
    let phrase_recovered = eth_keystore::decrypt_key(wallet_path, password)?;
    let phrase = String::from_utf8(phrase_recovered)?;
    let derive_path = get_derivation_path(account_index);
    let secret_key = SecretKey::new_from_mnemonic_phrase_with_path(&phrase, &derive_path)?;
    Ok(secret_key)
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
) -> Result<(), Error> {
    let mut screen = AlternateScreen::from(std::io::stdout());
    writeln!(screen, "{discreet_string}")?;
    screen.flush()?;
    println!("{continue_message}");
    wait_for_keypress();
    Ok(())
}

/// Encrypts the given mnemonic with the given password and writes it to a file at the given path.
///
/// The resulting wallet file will be a keystore as per the [Web3 Secret Storage Definition][1].
/// [1]: https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage.
pub(crate) fn write_wallet_from_mnemonic_and_password(
    wallet_path: &Path,
    mnemonic: &str,
    password: &str,
) -> Result<()> {
    let wallet_dir = wallet_path
        .parent()
        .ok_or_else(|| anyhow!("failed to retrieve parent directory of {wallet_path:?}"))?;
    let wallet_file_name = wallet_path
        .file_name()
        .and_then(|os_str| os_str.to_str())
        .ok_or_else(|| anyhow!("failed to retrieve file name from {wallet_path:?}"))?;
    let mnemonic_bytes: Vec<u8> = mnemonic.bytes().collect();
    eth_keystore::encrypt_key(
        wallet_dir,
        &mut rand::thread_rng(),
        mnemonic_bytes,
        password,
        Some(wallet_file_name),
    )
    .with_context(|| format!("failed to create keystore at {wallet_path:?}"))
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{
        save_dummy_wallet_file, with_tmp_folder, TEST_MNEMONIC, TEST_PASSWORD,
    };

    #[test]
    fn create_wallet_should_success() {
        with_tmp_folder(|tmp_folder| {
            let test_wallet_dir = tmp_folder.join("handle_wallet_dir_success_dir");
            let create_wallet_status = create_wallet(&test_wallet_dir).is_ok();
            assert!(create_wallet_status)
        });
    }

    #[test]
    fn create_wallet_should_fail() {
        with_tmp_folder(|tmp_folder| {
            let test_wallet_dir = tmp_folder.join("handle_wallet_dir_fail_dir");
            std::fs::create_dir_all(&test_wallet_dir).unwrap();
            let create_wallet_status = create_wallet(&test_wallet_dir).is_err();
            assert!(create_wallet_status)
        });
    }

    #[test]
    fn handle_absolute_path_argument() {
        let path_opt: Option<PathBuf> = Some(PathBuf::from("/forc_wallet_test_dir"));
        let path = path_opt.unwrap_or_else(default_wallet_path);
        let path_validation = validate_wallet_path(&path).is_err();
        assert!(path_validation)
    }
    #[test]
    fn derivation_path() {
        let derivation_path = get_derivation_path(0);
        assert_eq!(derivation_path, "m/44'/1179993420'/0'/0/0");
    }
    #[test]
    fn encrypt_and_save_phrase() {
        with_tmp_folder(|tmp_folder| {
            let wallet_path = tmp_folder.join("wallet.json");
            write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
                .unwrap();
            let phrase_recovered = eth_keystore::decrypt_key(wallet_path, TEST_PASSWORD).unwrap();
            let phrase = String::from_utf8(phrase_recovered).unwrap();
            assert_eq!(phrase, TEST_MNEMONIC)
        });
    }
    #[test]
    fn derive_account_by_index() {
        with_tmp_folder(|tmp_folder| {
            // initialize a wallet
            let wallet_path = tmp_folder.join("wallet.json");
            save_dummy_wallet_file(&wallet_path);
            // derive account with account index 0
            let account_ix = 0;
            let private_key = derive_account(&wallet_path, account_ix, TEST_PASSWORD).unwrap();
            assert_eq!(
                private_key.to_string(),
                "961bf9754dd036dd13b1d543b3c0f74062bc4ac668ea89d38ce8d712c591f5cf"
            )
        });
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use std::{panic, path::PathBuf};

    pub(crate) const TEST_MNEMONIC: &str = "rapid mechanic escape victory bacon switch soda math embrace frozen novel document wait motor thrive ski addict ripple bid magnet horse merge brisk exile";
    pub(crate) const TEST_PASSWORD: &str = "1234";

    /// Create a tmp folder and execute the given test function `f`
    pub(crate) fn with_tmp_folder<F>(f: F)
    where
        F: FnOnce(&PathBuf) + panic::UnwindSafe,
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
}
