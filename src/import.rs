use std::path::PathBuf;

use crate::{
    utils::{default_vault_path, request_new_password, save_phrase_to_disk, validate_vault_path},
    Error,
};
use fuels::signers::wallet::WalletUnlocked;

pub(crate) fn import_wallet_cli(path_opt: Option<String>) -> Result<(), Error> {
    let path = path_opt.map_or_else(default_vault_path, PathBuf::from);
    validate_vault_path(&path)?;
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
    save_phrase_to_disk(&path, &mnemonic, &password);

    Ok(())
}
