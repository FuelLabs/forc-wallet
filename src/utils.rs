use crate::Error;
use anyhow::{anyhow, Result};
use fuel_crypto::SecretKey;
use fuels_signers::wallet::DEFAULT_DERIVATION_PATH_PREFIX;
use home::home_dir;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::{fs, path::Path};
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
        let accounts_file_path = path.join(".accounts");
        if !accounts_file_path.exists() {
            Ok(Accounts { addresses: vec![] })
        } else {
            let account_file = fs::read_to_string(path.join(".accounts"))?;
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

/// Handles vault path creatation/retriveal. If should_create is true `handle_vault_path` will be
/// trying to create the vault path.
pub(crate) fn handle_vault_path(
    should_create: bool,
    path_argument: Option<String>,
) -> Result<PathBuf, Error> {
    let vault_path = handle_vault_path_argument(path_argument)?;
    if should_create {
        if vault_path.exists() {
            // TODO(?): add CLI interactivity to override
            return Err(Error::WalletError(format!(
            "Cannot import wallet at {:?}, the directory already exists! You can clear the given path and re-use the same path",
            vault_path
        )));
        }
        std::fs::create_dir_all(&vault_path)?;
    }
    Ok(vault_path)
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

pub(crate) fn derive_account_with_index<
    P: AsRef<std::path::Path> + std::convert::AsRef<std::ffi::OsStr>,
>(
    path: &P,
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
    format!("{}/{}'/0/0", DEFAULT_DERIVATION_PATH_PREFIX, account_index)
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
    writeln!(screen, "{}", discreet_string)?;
    screen.flush()?;
    println!("{}", continue_message);
    wait_for_keypress();
    Ok(())
}

/// Handle the default path argument and return the right path, error out if the path is not
/// relative to the home directory.
fn handle_vault_path_argument(path: Option<String>) -> Result<PathBuf, Error> {
    let vault_path = match path {
        Some(path) => PathBuf::from(path),
        None => {
            let mut default_relative = home_dir().unwrap();
            default_relative.push(DEFAULT_RELATIVE_VAULT_PATH);
            default_relative
        }
    };
    // If the path is not relative to the home directory, error out.
    // This should never happen if the `path` argument was `None`.
    if !vault_path.starts_with(home_dir().unwrap()) {
        return Err(Error::WalletError(format!(
            "Please provide a path relative to the home directory! Provided path: {:?}",
            vault_path
        )));
    }
    Ok(vault_path)
}

/// Encrypts and saves the mnemonic phrase to disk
pub(crate) fn save_phrase_to_disk<P: AsRef<std::path::Path> + std::fmt::Debug>(
    vault_path: &P,
    mnemonic: &str,
    password: &str,
) {
    let mnemonic_bytes: Vec<u8> = mnemonic.bytes().collect();
    eth_keystore::encrypt_key(
        &vault_path,
        &mut rand::thread_rng(),
        mnemonic_bytes,
        &password,
        Some(".wallet"),
    )
    .unwrap_or_else(|error| {
        panic!(
            "Cannot create eth_keystore at {:?}: {:?}",
            vault_path, error
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{save_dummy_wallet_file, with_tmp_folder, TEST_MNEMONIC};
    use serial_test::serial;

    #[test]
    #[serial]
    fn handle_vault_path_should_success() {
        with_tmp_folder(|tmp_folder| {
            let test_vault_path = tmp_folder.join("handle_vault_path_success_dir");
            let test_vault_path_str = test_vault_path
                .to_str()
                .map(|path_str| path_str.to_string());
            let vault_path_status = handle_vault_path(true, test_vault_path_str).is_ok();
            assert!(vault_path_status)
        });
    }

    #[test]
    #[serial]
    fn handle_vault_path_should_fail() {
        with_tmp_folder(|tmp_folder| {
            let test_vault_path = tmp_folder.join("handle_vault_path_fail_dir");
            std::fs::create_dir_all(&test_vault_path).unwrap();
            let test_vault_path_str = test_vault_path
                .to_str()
                .map(|path_str| path_str.to_string());
            let vault_path_status = handle_vault_path(true, test_vault_path_str).is_err();
            assert!(vault_path_status)
        });
    }

    #[test]
    fn handle_none_argument() -> Result<()> {
        let mut default_relative = home_dir().unwrap();
        default_relative.push(DEFAULT_RELATIVE_VAULT_PATH);
        assert_eq!(default_relative, handle_vault_path_argument(None)?);
        Ok(())
    }

    #[test]
    fn handle_relative_path_argument() -> Result<()> {
        let mut some_relative = home_dir().unwrap();
        some_relative.push("bimbamboum");
        let some_argument = Some(some_relative.display().to_string());
        assert_eq!(some_relative, handle_vault_path_argument(some_argument)?);
        Ok(())
    }

    #[test]
    fn handle_absolute_path_argument() {
        let absolute_path = "/bimbamboum".to_string();
        let result = handle_vault_path_argument(Some(absolute_path));
        let error_message = result.unwrap_err().to_string();
        assert!(error_message.contains("Please provide a path relative to the home directory!"));
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
            save_phrase_to_disk(&tmp_folder, TEST_MNEMONIC, "1234");
            let phrase_recovered =
                eth_keystore::decrypt_key(&tmp_folder.join(".wallet"), "1234").unwrap();
            let phrase = String::from_utf8(phrase_recovered).unwrap();
            assert_eq!(phrase, TEST_MNEMONIC)
        });
    }
    #[test]
    #[serial]
    fn derive_account_by_index() {
        with_tmp_folder(|tmp_folder| {
            // initialize a wallet
            save_dummy_wallet_file(&tmp_folder);
            // derive account with account index 0
            let private_key = derive_account_with_index(tmp_folder, 0, "1234").unwrap();
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
    pub(crate) fn save_dummy_wallet_file<P: AsRef<std::path::Path> + std::fmt::Debug>(path: &P) {
        save_phrase_to_disk(path, TEST_MNEMONIC, "1234");
    }
}
