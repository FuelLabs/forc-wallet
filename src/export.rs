use crate::utils::{
    derive_account_with_index, display_string_discreetly, handle_vault_path_argument,
};
use anyhow::Result;

pub(crate) fn export_account(path: Option<String>, account_index: usize) -> Result<()> {
    let vault_path = handle_vault_path_argument(path)?;

    let password = rpassword::prompt_password(
        "Please enter your password to decrypt initialized wallet's phrases: ",
    )?;
    let secret_key = derive_account_with_index(&vault_path, account_index, &password)?;
    let secret_key_string = format!("Secret key for account {}: {}\n", account_index, secret_key);
    display_string_discreetly(&secret_key_string, "### Press any key to complete. ###")?;

    Ok(())
}
