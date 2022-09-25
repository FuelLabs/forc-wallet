use crate::utils::{handle_vault_path_option, request_new_password};
use crate::Error;
use fuels::signers::wallet::WalletUnlocked;

pub(crate) fn import_wallet(path: Option<String>) -> Result<(), Error> {
    let vault_path = handle_vault_path_option(path)?;
    if vault_path.exists() {
        // TODO(?): add CLI interactivity to override
        return Err(Error::WalletError(format!(
            "Cannot import wallet at {:?}, the directory already exists!",
            vault_path
        )));
    }

    let mnemonic = rpassword::prompt_password("Please enter your mnemonic phrase: ")?;
    // Check users's phrase by trying to create a wallet from it
    if WalletUnlocked::new_from_mnemonic_phrase(&mnemonic, None).is_err() {
        return Err(Error::WalletError(
            "Cannot generate a wallet from provided mnemonics, please \
        check your mnemonic phrase"
                .to_string(),
        ));
    }
    // Encyrpt and store it
    let mnemonic_bytes: Vec<u8> = mnemonic.bytes().collect();
    let password = request_new_password();

    eth_keystore::encrypt_key(
        &vault_path,
        &mut rand::thread_rng(),
        mnemonic_bytes,
        &password,
        Some(".wallet"),
    )
    .unwrap_or_else(|error| {
        panic!(
            "Cannot import eth_keystore at {:?}: {:?}",
            vault_path, error
        )
    });
    Ok(())
}
