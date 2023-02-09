use std::path::PathBuf;

use crate::utils::{
    default_vault_path, derive_account_with_index, display_string_discreetly, validate_vault_path,
};
use anyhow::Result;

pub(crate) fn export_account_cli(path_opt: Option<PathBuf>, account_index: usize) -> Result<()> {
    let path = path_opt.unwrap_or_else(default_vault_path);
    validate_vault_path(&path)?;

    let password = rpassword::prompt_password(
        "Please enter your password to decrypt initialized wallet's phrases: ",
    )?;
    let secret_key = derive_account_with_index(&path, account_index, &password)?;
    let secret_key_string = format!("Secret key for account {account_index}: {secret_key}\n");
    display_string_discreetly(&secret_key_string, "### Press any key to complete. ###")?;

    Ok(())
}
