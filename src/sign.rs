use crate::account;
use anyhow::{Context, Result};
use clap::Subcommand;
use fuel_crypto::{Message, SecretKey, Signature};
use fuel_types::Bytes32;
use rpassword::prompt_password;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Sign a transaction ID.
    ///
    /// The tx ID is signed directly, i.e. it is not re-hashed before signing.
    ///
    /// Previously `tx`, though renamed in anticipation of support for signing transaction files.
    TxId { tx_id: fuel_types::Bytes32 },
    /// Read the file at the given path into bytes and sign the raw data.
    File { path: PathBuf },
    /// Sign the given string as a slice of bytes.
    String { string: String },
    /// Parse the given hex-encoded byte string and sign the raw bytes.
    ///
    /// All characters must be within the range '0'..='f'. Each character pair
    /// represents a single hex-encoded byte.
    ///
    /// The string may optionally start with the `0x` prefix which will be
    /// discarded before decoding and signing the remainder of the string.
    Hex { hex_string: String },
}

pub(crate) fn cli(wallet_path: &Path, account_ix: usize, cmd: Command) -> Result<()> {
    match cmd {
        Command::TxId { tx_id } => {
            sign_msg_with_wallet_account_cli(wallet_path, account_ix, &msg_from_hash32(tx_id))?
        }
        Command::File { path } => {
            sign_msg_with_wallet_account_cli(wallet_path, account_ix, &msg_from_file(&path)?)?
        }
        Command::Hex { hex_string } => sign_msg_with_wallet_account_cli(
            wallet_path,
            account_ix,
            &msg_from_hex_str(&hex_string)?,
        )?,
        Command::String { string } => {
            sign_msg_with_wallet_account_cli(wallet_path, account_ix, &Message::new(string))?
        }
    }
    Ok(())
}

pub(crate) fn private_key_cli(cmd: Command) -> Result<()> {
    match cmd {
        Command::TxId { tx_id } => sign_msg_with_private_key_cli(&msg_from_hash32(tx_id))?,
        Command::File { path } => sign_msg_with_private_key_cli(&msg_from_file(&path)?)?,
        Command::Hex { hex_string } => {
            sign_msg_with_private_key_cli(&msg_from_hex_str(&hex_string)?)?
        }
        Command::String { string } => sign_msg_with_private_key_cli(&Message::new(string))?,
    }
    Ok(())
}

fn sign_msg_with_private_key_cli(msg: &Message) -> Result<()> {
    let secret_key_input = prompt_password("Please enter the private key you wish to sign with: ")?;
    let secret_key = SecretKey::from_str(&secret_key_input)?;
    let signature = Signature::sign(&secret_key, msg);
    println!("Signature: {signature}");
    Ok(())
}

fn sign_msg_with_wallet_account_cli(
    wallet_path: &Path,
    account_ix: usize,
    msg: &Message,
) -> Result<()> {
    let password = prompt_password("Please enter your password: ")?;
    let signature = sign_msg_with_wallet_account(wallet_path, account_ix, msg, &password)?;
    println!("Signature: {signature}");
    Ok(())
}

fn sign_msg_with_wallet_account(
    wallet_path: &Path,
    account_ix: usize,
    msg: &Message,
    pw: &str,
) -> Result<Signature> {
    let secret_key = account::derive_secret_key(wallet_path, account_ix, pw)?;
    Ok(Signature::sign(&secret_key, msg))
}

// Cast the `Bytes32` directly to a message without normalizing it.
// We don't renormalize as a hash is already a normalized representation.
fn msg_from_hash32(hash: Bytes32) -> Message {
    unsafe { Message::from_bytes_unchecked(hash.into()) }
}

fn msg_from_file(path: &Path) -> Result<Message> {
    let bytes = std::fs::read(path).context("failed to read bytes from path")?;
    Ok(Message::new(bytes))
}

fn msg_from_hex_str(hex_str: &str) -> Result<Message> {
    let bytes = bytes_from_hex_str(hex_str)?;
    Ok(Message::new(bytes))
}

fn bytes_from_hex_str(mut hex_str: &str) -> Result<Vec<u8>> {
    // Strip the optional prefix.
    const OPTIONAL_PREFIX: &str = "0x";
    if hex_str.starts_with(OPTIONAL_PREFIX) {
        hex_str = &hex_str[OPTIONAL_PREFIX.len()..];
    }
    hex::decode(hex_str).context("failed to decode bytes from hex string")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{with_tmp_dir_and_wallet, TEST_PASSWORD};
    use fuel_crypto::Message;

    #[test]
    fn sign_tx_id() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            let tx_id = Bytes32::from_str(
                "0x6c226b276bd2028c0582229b6396f91801c913973487491b0262c5c7b3cd6e39",
            )
            .unwrap();
            let msg = msg_from_hash32(tx_id);
            let account_ix = 0;
            let sig =
                sign_msg_with_wallet_account(wallet_path, account_ix, &msg, TEST_PASSWORD).unwrap();
            assert_eq!(sig.to_string(), "bcf4651f072130aaf8925610e1d719b76e25b19b0a86779d3f4294964f1607cc95eb6c58eb37bf0510f618bd284decdf936c48ec6722df5472084e4098d54620");
        });
    }

    const TEST_STR: &str = "Blah blah blah";
    const EXPECTED_SIG: &str = "b0b2f29b52d95c1cba47ea7c7edeec6c84a0bd196df489e219f6f388b69d760479b994f4bae2d5f2abef7d5faf7d9f5ee3ea47ada4d15b7a7ee2777dcd7b36bb";

    #[test]
    fn sign_string() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            let msg = Message::new(TEST_STR);
            let account_ix = 0;
            let sig =
                sign_msg_with_wallet_account(wallet_path, account_ix, &msg, TEST_PASSWORD).unwrap();
            assert_eq!(sig.to_string(), EXPECTED_SIG);
        });
    }

    #[test]
    fn sign_file() {
        with_tmp_dir_and_wallet(|dir, wallet_path| {
            let path = dir.join("data");
            std::fs::write(&path, TEST_STR).unwrap();
            let msg = msg_from_file(&path).unwrap();
            let account_ix = 0;
            let sig =
                sign_msg_with_wallet_account(wallet_path, account_ix, &msg, TEST_PASSWORD).unwrap();
            assert_eq!(sig.to_string(), EXPECTED_SIG);
        });
    }

    #[test]
    fn sign_hex() {
        with_tmp_dir_and_wallet(|_dir, wallet_path| {
            let hex_encoded = hex::encode(TEST_STR);
            let msg = msg_from_hex_str(&hex_encoded).unwrap();
            let account_ix = 0;
            let sig =
                sign_msg_with_wallet_account(wallet_path, account_ix, &msg, TEST_PASSWORD).unwrap();
            assert_eq!(sig.to_string(), EXPECTED_SIG);
        });
    }
}
