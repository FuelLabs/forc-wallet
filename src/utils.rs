use crate::Error;
use anyhow::{anyhow, bail, Result};
use fuel_crypto::SecretKey;
use fuels_signers::wallet::DEFAULT_DERIVATION_PATH_PREFIX;
use home::home_dir;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use termion::screen::AlternateScreen;

pub(crate) const DEFAULT_RELATIVE_VAULT_PATH: &str = ".fuel/wallets/";

#[derive(Serialize, Deserialize)]
pub(crate) struct Accounts {
    addresses: Vec<String>,
}

impl Accounts {
    pub(crate) fn new(addresses: Vec<String>) -> Accounts {
        Accounts { addresses }
    }

    pub(crate) fn from_dir(path: &Path) -> Result<Accounts> {
        let path_buf = PathBuf::from(path);
        let accounts_file_path = path_buf.join(".accounts");
        if !accounts_file_path.exists() {
            Ok(Accounts { addresses: vec![] })
        } else {
            let account_file = fs::read_to_string(path_buf.join(".accounts"))?;
            let accounts = serde_json::from_str(&account_file)
                .map_err(|e| anyhow!("failed to parse .accounts: {}.", e))?;
            Ok(accounts)
        }
    }

    pub(crate) fn addresses(&self) -> &[String] {
        &self.addresses
    }
}

/// Create the `.accounts` file which holds the addresses of accounts derived so far
pub(crate) fn create_accounts_file(path: &Path, accounts: Vec<String>) -> Result<()> {
    let account_file = serde_json::to_string(&Accounts::new(accounts))?;
    fs::write(path.join(".accounts"), account_file)?;
    Ok(())
}

/// Creates the wallet vault if it does not exists.
pub(crate) fn create_vault(path: &Path) -> Result<()> {
    if path.exists() {
        bail!(format!("Cannot import wallet at {path:?}, the directory already exists! You can clear the given path and re-use the same path"))
    } else {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

/// If the path is not relative to the home directory, error out.
pub(crate) fn validate_vault_path(path: &Path) -> Result<()> {
    let home_dir = home_dir().ok_or_else(|| anyhow!("Cannot get home directory!"))?;
    if !path.starts_with(home_dir) {
        bail!(
            "Please provide a path relative to the home directory! Provided path: {:?}",
            path
        )
    }
    Ok(())
}

/// Returns default vault path which is $HOME/.fuel/wallets
pub(crate) fn default_vault_path() -> PathBuf {
    let home_dir = home_dir().expect("Cannot get home directory!");
    home_dir.join(DEFAULT_RELATIVE_VAULT_PATH)
}

/// Returns the number of the accounts derived so far by reading the .accounts file from given path
pub(crate) fn number_of_derived_accounts(path: &Path) -> usize {
    let accounts = Accounts::from_dir(path);
    if let Ok(accounts) = accounts {
        accounts.addresses().len()
    } else {
        0
    }
}

pub(crate) fn derive_account_with_index(
    path: &Path,
    account_index: usize,
    password: &str,
) -> Result<SecretKey> {
    let path_buf = PathBuf::from(path);
    let phrase_recovered = eth_keystore::decrypt_key(path_buf.join(".wallet"), password)?;
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

/// Encrypts and saves the mnemonic phrase to disk
pub(crate) fn save_phrase_to_disk(vault_path: &Path, mnemonic: &str, password: &str) {
    let mnemonic_bytes: Vec<u8> = mnemonic.bytes().collect();
    eth_keystore::encrypt_key(
        vault_path,
        &mut rand::thread_rng(),
        mnemonic_bytes,
        password,
        Some(".wallet"),
    )
    .unwrap_or_else(|error| panic!("Cannot create eth_keystore at {vault_path:?}: {error:?}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{
        save_dummy_wallet_file, with_tmp_folder, TEST_MNEMONIC, TEST_PASSWORD,
    };
    use serial_test::serial;

    #[test]
    #[serial]
    fn create_vault_should_success() {
        with_tmp_folder(|tmp_folder| {
            let test_vault_path = tmp_folder.join("handle_vault_path_success_dir");
            let create_vault_status = create_vault(&test_vault_path).is_ok();
            assert!(create_vault_status)
        });
    }

    #[test]
    #[serial]
    fn create_vault_should_fail() {
        with_tmp_folder(|tmp_folder| {
            let test_vault_path = tmp_folder.join("handle_vault_path_fail_dir");
            std::fs::create_dir_all(&test_vault_path).unwrap();
            let create_vault_status = create_vault(&test_vault_path).is_err();
            assert!(create_vault_status)
        });
    }

    #[test]
    fn handle_none_argument() {
        let path_opt: Option<PathBuf> = None;
        let path = path_opt.unwrap_or_else(default_vault_path);
        validate_vault_path(&path).unwrap();
        let home_dir = home_dir().unwrap();
        let default_path = home_dir.join(DEFAULT_RELATIVE_VAULT_PATH);
        assert_eq!(path, default_path)
    }

    #[test]
    fn handle_relative_path_argument() {
        let home_dir = home_dir().unwrap();
        let test_dir = home_dir.join("forc_wallet_test_dir");
        let path_opt = Some(test_dir);
        let path = path_opt.unwrap_or_else(default_vault_path);
        validate_vault_path(&path).unwrap();
        let default_path = home_dir.join("forc_wallet_test_dir");
        assert_eq!(path, default_path)
    }

    #[test]
    fn handle_absolute_path_argument() {
        let path_opt: Option<PathBuf> = Some(PathBuf::from("/forc_wallet_test_dir"));
        let path = path_opt.unwrap_or_else(default_vault_path);
        let path_validation = validate_vault_path(&path).is_err();
        assert!(path_validation)
    }
    #[test]
    fn derivation_path() {
        let derivation_path = get_derivation_path(0);
        assert_eq!(derivation_path, "m/44'/1179993420'/0'/0/0");
    }
    #[test]
    #[serial]
    fn encrypt_and_save_phrase() {
        with_tmp_folder(|tmp_folder| {
            save_phrase_to_disk(tmp_folder, TEST_MNEMONIC, TEST_PASSWORD);
            let phrase_recovered =
                eth_keystore::decrypt_key(tmp_folder.join(".wallet"), TEST_PASSWORD).unwrap();
            let phrase = String::from_utf8(phrase_recovered).unwrap();
            assert_eq!(phrase, TEST_MNEMONIC)
        });
    }
    #[test]
    #[serial]
    fn derive_account_by_index() {
        with_tmp_folder(|tmp_folder| {
            // initialize a wallet
            save_dummy_wallet_file(tmp_folder);
            // derive account with account index 0
            let private_key = derive_account_with_index(tmp_folder, 0, TEST_PASSWORD).unwrap();
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
    use home::home_dir;
    use std::{panic, path::PathBuf};

    pub(crate) const TEST_MNEMONIC: &str = "rapid mechanic escape victory bacon switch soda math embrace frozen novel document wait motor thrive ski addict ripple bid magnet horse merge brisk exile";

    pub(crate) const TEST_PASSWORD: &str = "1234";

    /// Create a tmp folder and execute the given test function `f`
    pub(crate) fn with_tmp_folder<F>(f: F)
    where
        F: FnOnce(&PathBuf) + panic::UnwindSafe,
    {
        let home_dir = home_dir().unwrap();
        let tmp_dir = home_dir.join("forc-wallet-tests-tmp");
        if tmp_dir.exists() {
            std::fs::remove_dir_all(&tmp_dir).unwrap();
        }
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let panic = panic::catch_unwind(|| f(&tmp_dir));
        std::fs::remove_dir_all(&tmp_dir).unwrap();
        if let Err(e) = panic {
            panic::resume_unwind(e);
        }
    }
    /// Saves a default test mnemonic to the disk
    pub(crate) fn save_dummy_wallet_file(path: &Path) {
        save_phrase_to_disk(path, TEST_MNEMONIC, TEST_PASSWORD);
    }
}
