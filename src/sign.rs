use crate::account;
use anyhow::Result;
use fuel_crypto::{Message, SecretKey, Signature};
use fuel_types::Bytes32;
use rpassword::prompt_password;
use std::{path::Path, str::FromStr};

fn sign_transaction(
    tx_id: Bytes32,
    account_index: usize,
    password: &str,
    path: &Path,
) -> Result<Signature> {
    let secret_key = account::derive_secret_key(path, account_index, password)?;
    sign_transaction_with_private_key(tx_id, secret_key)
}

fn sign_transaction_with_private_key(tx_id: Bytes32, secret_key: SecretKey) -> Result<Signature> {
    let message_hash = unsafe { Message::from_bytes_unchecked(*tx_id) };
    let sig = Signature::sign(&secret_key, &message_hash);
    Ok(sig)
}

pub(crate) fn sign_transaction_with_private_key_cli(tx_id: Bytes32) -> Result<()> {
    let secret_key_input = prompt_password("Please enter the private key you wish to sign with: ")?;
    let secret_key = SecretKey::from_str(&secret_key_input)?;
    let signature = sign_transaction_with_private_key(tx_id, secret_key)?;
    println!("Signature: {signature}");
    Ok(())
}

pub(crate) fn sign_transaction_cli(
    wallet_path: &Path,
    tx_id: Bytes32,
    account_index: usize,
) -> Result<()> {
    let password = prompt_password("Please enter your password: ")?;
    let signature = sign_transaction(tx_id, account_index, &password, wallet_path)?;
    println!("Signature: {signature}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{save_dummy_wallet_file, with_tmp_folder, TEST_PASSWORD};
    #[test]
    fn sign_dummy_transaction() {
        with_tmp_folder(|tmp_folder| {
            let wallet_path = tmp_folder.join("wallet.json");
            // initialize a wallet
            save_dummy_wallet_file(&wallet_path);
            let tx_id = Bytes32::from_str(
                "0x6c226b276bd2028c0582229b6396f91801c913973487491b0262c5c7b3cd6e39",
            )
            .unwrap();
            let sig = sign_transaction(tx_id, 0, TEST_PASSWORD, &wallet_path).unwrap();
            assert_eq!(sig.to_string(), "bcf4651f072130aaf8925610e1d719b76e25b19b0a86779d3f4294964f1607cc95eb6c58eb37bf0510f618bd284decdf936c48ec6722df5472084e4098d54620");
        });
    }
}
