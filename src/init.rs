use crate::{
    utils::{
        display_string_discreetly, handle_vault_path_argument, request_new_password,
        save_phrase_to_disk,
    },
    Error,
};
use fuels::signers::wallet::generate_mnemonic_phrase;

pub(crate) fn init_wallet(path: Option<String>) -> Result<(), Error> {
    let vault_path = handle_vault_path_argument(path)?;
    if vault_path.exists() {
        // TODO(?): add CLI interactivity to override
        return Err(Error::WalletError(format!(
            "Cannot init vault at {:?}, the directory already exists! You can clear the given path and re-use the same path",
            vault_path
        )));
    }
    std::fs::create_dir_all(&vault_path)?;

    let password = request_new_password();
    // Generate mnemonic phrase
    let mnemonic = generate_mnemonic_phrase(&mut rand::thread_rng(), 24)?;
    // Encrypt and store it
    save_phrase_to_disk(&vault_path, &mnemonic, &password);

    let mnemonic_string = format!("Wallet mnemonic phrase: {}\n", mnemonic);
    display_string_discreetly(
        &mnemonic_string,
        "### Do not share or lose this mnemonic phrase! Press any key to complete. ###",
    )?;
    Ok(())
}
