use crate::{
    utils::{handle_vault_path, request_new_password, save_phrase_to_disk},
    Error,
};
use fuels::signers::wallet::WalletUnlocked;

pub(crate) fn import_wallet_cli(path: Option<String>) -> Result<(), Error> {
    let vault_path = handle_vault_path(true, path)?;
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
