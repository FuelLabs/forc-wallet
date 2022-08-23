use std::str::FromStr;

use crate::{utils::get_account_from_store, DEFAULT_WALLETS_VAULT_PATH};
use anyhow::Result;
use fuel_crypto::Message;
use fuels::prelude::*;
use fuels_signers::{fuel_crypto::fuel_types::AssetId, Signer};

pub(crate) async fn sign_transaction_manually(
    id: &str,
    account_index: usize,
    path: Option<String>,
) -> Result<(), Error> {
    let asset_id = AssetId::from_str(id).unwrap();
    let wallet = get_account_from_store(
        account_index,
        &path.unwrap_or_else(|| DEFAULT_WALLETS_VAULT_PATH.to_string()),
    )?;
    let message = unsafe { Message::from_bytes_unchecked(*asset_id) };
    let sig = wallet.sign_message(message).await?;
    println!("sig: {sig}");
    Ok(())
}
