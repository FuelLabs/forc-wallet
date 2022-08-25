use crate::utils::{derive_account_with_index, DEFAULT_WALLETS_VAULT_PATH};
use anyhow::{anyhow, Result};
use fuel_crypto::Message;
use fuels::prelude::*;
use fuels_signers::{fuel_crypto::fuel_types::AssetId, Signer};
use std::{path::PathBuf, str::FromStr};

pub(crate) async fn sign_transaction_manually(
    id: &str,
    account_index: usize,
    path: Option<String>,
) -> Result<(), Error> {
    let wallet_path = match &path {
        Some(path) => PathBuf::from(path),
        None => home::home_dir().unwrap().join(DEFAULT_WALLETS_VAULT_PATH),
    };
    let asset_id = AssetId::from_str(id).map_err(|e| anyhow!("{}", e))?;
    let wallet = derive_account_with_index(&wallet_path, account_index)?;
    let message = unsafe { Message::from_bytes_unchecked(*asset_id) };
    let sig = wallet.sign_message(message).await?;
    println!("Signature: {sig}");
    Ok(())
}
