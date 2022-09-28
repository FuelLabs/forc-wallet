use crate::utils::{derive_account_with_index, DEFAULT_RELATIVE_VAULT_PATH};
use anyhow::{anyhow, Result};
use fuel_crypto::{Message, Signature};
use fuel_types::Bytes32;
use fuels::prelude::*;
use std::{path::PathBuf, str::FromStr};

pub(crate) async fn sign_transaction_manually(
    id: &str,
    account_index: usize,
    path: Option<String>,
) -> Result<(), Error> {
    let vault_path = match &path {
        Some(path) => PathBuf::from(path),
        None => home::home_dir().unwrap().join(DEFAULT_RELATIVE_VAULT_PATH),
    };
    let tx_id = Bytes32::from_str(id).map_err(|e| anyhow!("{}", e))?;
    let secret_key = derive_account_with_index(&vault_path, account_index)?;
    let message_hash = unsafe { Message::from_bytes_unchecked(*tx_id) };
    let sig = Signature::sign(&secret_key, &message_hash);
    println!("Signature: {sig}");
    Ok(())
}
