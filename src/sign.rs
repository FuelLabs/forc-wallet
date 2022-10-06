use crate::utils::{derive_account_with_index, request_new_password, DEFAULT_RELATIVE_VAULT_PATH};
use anyhow::{anyhow, Result};
use fuel_crypto::{Message, Signature};
use fuel_types::Bytes32;
use fuels::prelude::*;
use std::{path::PathBuf, str::FromStr};

fn sign_transaction<P>(
    tx_id: Bytes32,
    account_index: usize,
    password: &str,
    path: P,
) -> Result<Signature>
where
    P: Into<PathBuf>,
{
    let secret_key = derive_account_with_index(path, account_index, password)?;
    let message_hash = unsafe { Message::from_bytes_unchecked(*tx_id) };
    let sig = Signature::sign(&secret_key, &message_hash);
    Ok(sig)
}

pub(crate) fn sign_transaction_cli(
    id: &str,
    account_index: usize,
    path: Option<String>,
) -> Result<(), Error> {
    let vault_path = match &path {
        Some(path) => PathBuf::from(path),
        None => home::home_dir().unwrap().join(DEFAULT_RELATIVE_VAULT_PATH),
    };
    let password = request_new_password();
    let tx_id = Bytes32::from_str(id).map_err(|e| anyhow!("{}", e))?;
    let signature = sign_transaction(tx_id, account_index, &password, &vault_path)?;
    println!("Signature: {signature}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{save_dummy_wallet_file, with_tmp_folder, TEST_PASSWORD};
    use serial_test::serial;
    #[test]
    #[serial]
    fn sign_dummy_transaction() {
        with_tmp_folder(|tmp_folder| {
            // initialize a wallet
            save_dummy_wallet_file(&tmp_folder);
            let tx_id = Bytes32::from_str(
                "0x6c226b276bd2028c0582229b6396f91801c913973487491b0262c5c7b3cd6e39",
            )
            .unwrap();
            let sig = sign_transaction(tx_id, 0, TEST_PASSWORD, tmp_folder).unwrap();
            assert_eq!(sig.to_string(), "bcf4651f072130aaf8925610e1d719b76e25b19b0a86779d3f4294964f1607cc95eb6c58eb37bf0510f618bd284decdf936c48ec6722df5472084e4098d54620");
        });
    }
}
