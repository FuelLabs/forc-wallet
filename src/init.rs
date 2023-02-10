use crate::{
    utils::{
        create_vault, default_wallet_path, display_string_discreetly, request_new_password,
        save_phrase_to_disk, validate_wallet_path,
    },
    Error,
};
use fuels::signers::wallet::generate_mnemonic_phrase;
use std::path::{Path, PathBuf};

fn init_wallet(path: &Path, password: &str) -> Result<String, Error> {
    // Generate mnemonic phrase
    let mnemonic = generate_mnemonic_phrase(&mut rand::thread_rng(), 24)?;
    // Encrypt and store it
    save_phrase_to_disk(path, &mnemonic, password);
    Ok(mnemonic)
}

pub(crate) fn init_wallet_cli(path_opt: Option<PathBuf>) -> Result<(), Error> {
    let path = path_opt.unwrap_or_else(default_wallet_path);
    validate_wallet_path(&path)?;
    create_vault(&path)?;
    let password = request_new_password();
    let mnemonic = init_wallet(&path, &password)?;
    let mnemonic_string = format!("Wallet mnemonic phrase: {mnemonic}\n");
    display_string_discreetly(
        &mnemonic_string,
        "### Do not share or lose this mnemonic phrase! Press any key to complete. ###",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{with_tmp_folder, TEST_PASSWORD};
    use fuels::signers::WalletUnlocked;
    use serial_test::serial;

    #[serial]
    #[test]
    fn initialize_wallet() {
        with_tmp_folder(|tmp_folder| {
            let mnemonic = init_wallet(tmp_folder, TEST_PASSWORD).unwrap();
            let wallet_success = WalletUnlocked::new_from_mnemonic_phrase(&mnemonic, None).is_ok();
            assert!(wallet_success)
        })
    }
}
