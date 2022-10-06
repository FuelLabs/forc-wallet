use crate::{
    utils::{
        display_string_discreetly, handle_vault_path, request_new_password, save_phrase_to_disk,
    },
    Error,
};
use fuels::signers::wallet::generate_mnemonic_phrase;

fn init_wallet<P: AsRef<std::path::Path> + std::fmt::Debug>(
    path: &P,
    password: &str,
) -> Result<String, Error> {
    // Generate mnemonic phrase
    let mnemonic = generate_mnemonic_phrase(&mut rand::thread_rng(), 24)?;
    // Encrypt and store it
    save_phrase_to_disk(&path, &mnemonic, password);
    Ok(mnemonic)
}

pub(crate) fn init_wallet_cli(path: Option<String>) -> Result<(), Error> {
    let vault_path = handle_vault_path(true, path)?;
    let password = request_new_password();
    let mnemonic = init_wallet(&vault_path, &password)?;
    let mnemonic_string = format!("Wallet mnemonic phrase: {}\n", mnemonic);
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
