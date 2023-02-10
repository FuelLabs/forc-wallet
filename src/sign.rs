use crate::utils::{
    default_wallet_path, derive_account_with_index, request_new_password, validate_wallet_path,
};
use anyhow::{anyhow, Result};
use fuel_crypto::{Message, SecretKey, Signature};
use fuel_types::Bytes32;
use fuels::prelude::*;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

fn sign_transaction(
    tx_id: Bytes32,
    account_index: usize,
    password: &str,
    path: &Path,
) -> Result<Signature> {
    let secret_key = derive_account_with_index(path, account_index, password)?;
    sign_transaction_with_private_key(tx_id, secret_key)
}

fn sign_transaction_with_private_key(tx_id: Bytes32, secret_key: SecretKey) -> Result<Signature> {
    let message_hash = unsafe { Message::from_bytes_unchecked(*tx_id) };
    let sig = Signature::sign(&secret_key, &message_hash);
    Ok(sig)
}

pub(crate) fn sign_transaction_with_private_key_cli(tx_id: &str) -> Result<()> {
    let tx_id = Bytes32::from_str(tx_id).map_err(|e| anyhow!("{}", e))?;
    let secret_key_input = request_new_password();
    let secret_key = SecretKey::from_str(&secret_key_input)?;
    let signature = sign_transaction_with_private_key(tx_id, secret_key)?;
    println!("Signature: {signature}");
    Ok(())
}

pub(crate) fn sign_transaction_cli(
    id: &str,
    account_index: usize,
    path_opt: Option<PathBuf>,
) -> Result<(), Error> {
    let path = path_opt.map_or_else(default_wallet_path, PathBuf::from);
    validate_wallet_path(&path)?;
    let password = request_new_password();
    let tx_id = Bytes32::from_str(id).map_err(|e| anyhow!("{}", e))?;
    let signature = sign_transaction(tx_id, account_index, &password, &path)?;
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
            save_dummy_wallet_file(tmp_folder);
            let tx_id = Bytes32::from_str(
                "0x6c226b276bd2028c0582229b6396f91801c913973487491b0262c5c7b3cd6e39",
            )
            .unwrap();
            let sig = sign_transaction(tx_id, 0, TEST_PASSWORD, tmp_folder).unwrap();
            assert_eq!(sig.to_string(), "bcf4651f072130aaf8925610e1d719b76e25b19b0a86779d3f4294964f1607cc95eb6c58eb37bf0510f618bd284decdf936c48ec6722df5472084e4098d54620");
        });
    }
}
