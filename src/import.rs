use crate::{
    utils::{handle_vault_path_argument, request_new_password, save_phrase_to_disk},
    Error,
};
use fuels::signers::wallet::WalletUnlocked;

pub(crate) fn import_wallet(path: Option<String>) -> Result<(), Error> {
    let vault_path = handle_vault_path_argument(path)?;
    if vault_path.exists() {
        // TODO(?): add CLI interactivity to override
        return Err(Error::WalletError(format!(
            "Cannot import wallet at {:?}, the directory already exists! You can clear the given path and re-use the same path",
            vault_path
        )));
    }
    std::fs::create_dir_all(&vault_path)?;

    let mnemonic = rpassword::prompt_password("Please enter your mnemonic phrase: ")?;
    // Check users's phrase by trying to create a wallet from it
    if WalletUnlocked::new_from_mnemonic_phrase(&mnemonic, None).is_err() {
        return Err(Error::WalletError(
            "Cannot generate a wallet from provided mnemonics, please \
        check your mnemonic phrase"
                .to_string(),
        ));
    }
    let password = request_new_password();
    // Encyrpt and store it
    save_phrase_to_disk(&vault_path, &mnemonic, &password);

    Ok(())
}
