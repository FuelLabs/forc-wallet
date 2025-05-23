use anyhow::{Context, Ok, Result, anyhow, bail};
use eth_keystore::EthKeystore;
use forc_tracing::println_warning;
use home::home_dir;
use std::{
    fs,
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
};

pub const DEFAULT_DERIVATION_PATH_PREFIX: &str = "m/44'/1179993420'";

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
        println_warning("Passwords do not match -- try again!");
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
    // The wallet should have been removed in `ensure_no_wallet_exists`, but we check again to be safe.
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
    let remove_wallet = || {
        if wallet_path.is_dir() {
            fs::remove_dir_all(wallet_path).unwrap();
        } else {
            fs::remove_file(wallet_path).unwrap();
        }
    };

    if wallet_path.exists() && fs::metadata(wallet_path)?.len() > 0 {
        if force {
            println_warning(&format!(
                "Because the `--force` argument was supplied, the wallet at {} will be removed.",
                wallet_path.display(),
            ));
            remove_wallet();
        } else {
            println_warning(&format!(
                "There is an existing wallet at {}. \
                Do you wish to replace it with a new wallet? (y/N) ",
                wallet_path.display(),
            ));
            let mut need_replace = String::new();
            reader.read_line(&mut need_replace).unwrap();
            if need_replace.trim() == "y" {
                remove_wallet();
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
    use crate::utils::test_utils::{TEST_MNEMONIC, TEST_PASSWORD};
    // simulate input
    const INPUT_NOP: &[u8; 1] = b"\n";
    const INPUT_YES: &[u8; 2] = b"y\n";
    const INPUT_NO: &[u8; 2] = b"n\n";

    /// Represents the possible serialized states of a wallet.
    /// Used primarily for simulating wallet creation and serialization processes.
    enum WalletSerializedState {
        Empty,
        WithData(String),
    }

    /// Simulates the serialization of a wallet to a file, optionally including dummy data.
    /// Primarily used to test if checks for wallet file existence are functioning correctly.
    fn serialize_wallet_to_file(wallet_path: &Path, state: WalletSerializedState) {
        // Create the wallet file if it does not exist.
        if !wallet_path.exists() {
            fs::File::create(wallet_path).unwrap();
        }

        // Write content to the wallet file based on the specified state.
        if let WalletSerializedState::WithData(data) = state {
            fs::write(wallet_path, data).unwrap();
        }
    }

    fn remove_wallet(wallet_path: &Path) {
        if wallet_path.exists() {
            fs::remove_file(wallet_path).unwrap();
        }
    }

    #[test]
    fn handle_absolute_path_argument() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let tmp_dir_abs = tmp_dir.path().canonicalize().unwrap();
        let wallet_path = tmp_dir_abs.join("wallet.json");
        write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
            .unwrap();
        load_wallet(&wallet_path).unwrap();
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
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let wallet_path = tmp_dir.path().join("wallet.json");
        write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
            .unwrap();
        let phrase_recovered = eth_keystore::decrypt_key(wallet_path, TEST_PASSWORD).unwrap();
        let phrase = String::from_utf8(phrase_recovered).unwrap();
        assert_eq!(phrase, TEST_MNEMONIC)
    }

    #[test]
    fn write_wallet() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let wallet_path = tmp_dir.path().join("wallet.json");
        write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
            .unwrap();
        load_wallet(&wallet_path).unwrap();
    }

    #[test]
    #[should_panic]
    fn write_wallet_to_existing_file_should_fail() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let wallet_path = tmp_dir.path().join("wallet.json");
        write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
            .unwrap();
        write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
            .unwrap();
    }

    #[test]
    fn write_wallet_subdir() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let wallet_path = tmp_dir.path().join("path").join("to").join("wallet.json");
        write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
            .unwrap();
        load_wallet(&wallet_path).unwrap();
    }

    #[test]
    fn test_ensure_no_wallet_exists_no_wallet() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let wallet_path = tmp_dir.path().join("wallet.json");
        remove_wallet(&wallet_path);
        ensure_no_wallet_exists(&wallet_path, false, &INPUT_NOP[..]).unwrap();
    }

    #[test]
    fn test_ensure_no_wallet_exists_exists_wallet() {
        // case: wallet path exist without --force and input[yes]
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let wallet_path = tmp_dir.path().join("wallet.json");
        serialize_wallet_to_file(&wallet_path, WalletSerializedState::Empty);
        ensure_no_wallet_exists(&wallet_path, false, &INPUT_YES[..]).unwrap();

        // case: wallet path exist with --force
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let wallet_path = tmp_dir.path().join("empty_wallet.json");
        serialize_wallet_to_file(&wallet_path, WalletSerializedState::Empty);

        // Empty file should not trigger the replacement prompt
        ensure_no_wallet_exists(&wallet_path, false, &INPUT_YES[..]).unwrap();
        assert!(wallet_path.exists(), "Empty file should remain untouched");
    }

    #[test]
    fn test_ensure_no_wallet_exists_nonempty_file() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let wallet_path = tmp_dir.path().join("nonempty_wallet.json");

        // Create non-empty file
        serialize_wallet_to_file(
            &wallet_path,
            WalletSerializedState::WithData("some wallet content".to_string()),
        );

        // Test with --force flag
        ensure_no_wallet_exists(&wallet_path, true, &INPUT_NO[..]).unwrap();
        assert!(
            !wallet_path.exists(),
            "File should be removed with --force flag"
        );

        // Test with user confirmation (yes)
        serialize_wallet_to_file(
            &wallet_path,
            WalletSerializedState::WithData("some wallet content".to_string()),
        );
        ensure_no_wallet_exists(&wallet_path, false, &INPUT_YES[..]).unwrap();
        assert!(
            !wallet_path.exists(),
            "File should be removed after user confirmation"
        );

        // Test with user rejection (no)
        serialize_wallet_to_file(
            &wallet_path,
            WalletSerializedState::WithData("some wallet content".to_string()),
        );
        let result = ensure_no_wallet_exists(&wallet_path, false, &INPUT_NO[..]);
        assert!(
            result.is_err(),
            "Should error when user rejects file removal"
        );
        assert!(
            wallet_path.exists(),
            "File should remain when user rejects removal"
        );
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use fuels::accounts::provider::Provider;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use std::{panic, path::Path};

    pub(crate) const TEST_MNEMONIC: &str = "rapid mechanic escape victory bacon switch soda math embrace frozen novel document wait motor thrive ski addict ripple bid magnet horse merge brisk exile";
    pub(crate) const TEST_PASSWORD: &str = "1234";

    /// Creates temp dir with a temp/test wallet.
    pub(crate) fn with_tmp_dir_and_wallet<F>(f: F)
    where
        F: FnOnce(&Path, &Path) + panic::UnwindSafe,
    {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let wallet_path = tmp_dir.path().join("wallet.json");
        write_wallet_from_mnemonic_and_password(&wallet_path, TEST_MNEMONIC, TEST_PASSWORD)
            .unwrap();
        f(tmp_dir.path(), &wallet_path);
    }

    /// Returns a mock provider with a mock fuel-core server that responds to the nodeInfo graphql query.
    /// Note: the raw JSON response will need to be updated if the schema changes.
    pub(crate) async fn mock_provider() -> Provider {
        let mock_server = MockServer::start().await;

        // Since [fuel_core_client::client::types::NodeInfo] does not implement [serde::Serialize],
        // we use raw JSON for the response.
        // If you get an error like "Error making HTTP request: error decoding response body", there has
        // likely been a change to the schema and the raw JSON response will need to be updated to match
        // the new schema.
        let node_info_res_body = json!({
            "data": {
                "nodeInfo": {
                    "utxoValidation": true,
                    "vmBacktrace": false,
                    "maxTx": "160000",
                    "maxGas": "30000000000",
                    "maxSize": "131072000",
                    "maxDepth": "32",
                    "nodeVersion": "0.41.9",
                    "indexation": {
                        "balances": false,
                        "coinsToSpend": false,
                        "assetMetadata": false
                    },
                    "txPoolStats": {
                        "txCount": "0",
                        "totalGas": "0",
                        "totalSize": "0"
                    }
                }
            }
        });

        let node_info_response = ResponseTemplate::new(200).set_body_json(node_info_res_body);

        Mock::given(method("POST"))
            .and(path("/v1/graphql"))
            .respond_with(node_info_response)
            .mount(&mock_server)
            .await;

        Provider::connect(mock_server.uri())
            .await
            .expect("mock provider")
    }
}
