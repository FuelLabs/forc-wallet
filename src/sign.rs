use crate::account;
use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use fuel_crypto::{Message, SecretKey, Signature};
use fuel_types::Bytes32;
use rpassword::prompt_password;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

/// Sign some data (e.g. a transaction ID, a file, a string, or a hex-string)
/// using either a wallet account or a private key.
#[derive(Debug, Args)]
pub struct Sign {
    /// Sign using the wallet account at the given index.
    /// Uses a discrete interactive prompt for password input.
    #[clap(long, value_name = "ACCOUNT_INDEX")]
    pub account: Option<usize>,
    /// Sign using a private key.
    /// Uses a discrete interactive prompt for collecting the private key.
    #[clap(long)]
    pub private: bool,
    /// Sign by passing the private key directly.
    ///
    /// WARNING: This is primarily provided for non-interactive testing. Using this flag is
    /// prone to leaving your private key exposed in your shell command history!
    #[clap(long)]
    pub private_key: Option<SecretKey>,
    /// Directly provide the wallet password when signing with an account.
    ///
    /// WARNING: This is primarily provided for non-interactive testing. Using this flag is
    /// prone to leaving your password exposed in your shell command history!
    #[clap(long)]
    pub password: Option<String>,
    #[clap(subcommand)]
    pub data: Data,
}

/// The data that is to be signed.
#[derive(Debug, Subcommand)]
pub enum Data {
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

pub(crate) fn cli(wallet_path: &Path, sign: Sign) -> Result<()> {
    let Sign {
        account,
        private,
        private_key,
        password,
        data,
    } = sign;
    match (account, password, private, private_key) {
        // Provided an account index, so we'll request the password.
        (Some(acc_ix), None, false, None) => wallet_account_cli(wallet_path, acc_ix, data)?,
        // Provided the password as a flag, so no need for interactive step.
        (Some(acc_ix), Some(pw), false, None) => {
            let msg = msg_from_data(data)?;
            let sig = sign_msg_with_wallet_account(wallet_path, acc_ix, &msg, &pw)?;
            println!("Signature: {sig}");
        }
        // Provided the private key to sign with directly.
        (None, None, _, Some(priv_key)) => {
            let msg = msg_from_data(data)?;
            let sig = Signature::sign(&priv_key, &msg);
            println!("Signature: {sig}");
        }
        // Sign with a private key interactively.
        (None, None, true, None) => private_key_cli(data)?,
        // TODO: If the user provides neither account or private flags, ask in interactive mode?
        _ => bail!(
            "Unexpected set of options passed to `forc wallet sign`.\n  \
                 To sign with a wallet account, use `forc wallet sign --account <index> <data>`\n  \
                 To sign with a private key, use `forc wallet sign --private <data>`",
        ),
    }
    Ok(())
}

pub(crate) fn wallet_account_cli(wallet_path: &Path, account_ix: usize, data: Data) -> Result<()> {
    let msg = msg_from_data(data)?;
    sign_msg_with_wallet_account_cli(wallet_path, account_ix, &msg)
}

pub(crate) fn private_key_cli(data: Data) -> Result<()> {
    match data {
        Data::TxId { tx_id } => sign_msg_with_private_key_cli(&msg_from_hash32(tx_id))?,
        Data::File { path } => sign_msg_with_private_key_cli(&msg_from_file(&path)?)?,
        Data::Hex { hex_string } => sign_msg_with_private_key_cli(&msg_from_hex_str(&hex_string)?)?,
        Data::String { string } => sign_msg_with_private_key_cli(&Message::new(string))?,
    }
    Ok(())
}

fn sign_msg_with_private_key_cli(msg: &Message) -> Result<()> {
    let secret_key_input = prompt_password("Please enter the private key you wish to sign with: ")?;
    let signature = sign_with_private_key_str(msg, &secret_key_input)?;
    println!("Signature: {signature}");
    Ok(())
}

fn sign_with_private_key_str(msg: &Message, priv_key_input: &str) -> Result<Signature> {
    let secret_key = SecretKey::from_str(priv_key_input)?;
    Ok(Signature::sign(&secret_key, msg))
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

fn msg_from_data(data: Data) -> Result<Message> {
    let msg = match data {
        Data::TxId { tx_id } => msg_from_hash32(tx_id),
        Data::File { path } => msg_from_file(&path)?,
        Data::Hex { hex_string } => msg_from_hex_str(&hex_string)?,
        Data::String { string } => Message::new(string),
    };
    Ok(msg)
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
            // The hex prefix should be ignored if it exists.
            let prefixed = format!("0x{hex_encoded}");
            let prefixed_msg = msg_from_hex_str(&prefixed).unwrap();
            assert_eq!(msg, prefixed_msg);
        });
    }
}
