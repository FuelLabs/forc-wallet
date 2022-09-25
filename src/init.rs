use std::io::Write;

use crate::Error;
use fuels::signers::wallet::generate_mnemonic_phrase;
use termion::screen::AlternateScreen;

use crate::utils::{handle_vault_path_argument, request_new_password, wait_for_keypress};

pub(crate) fn init_wallet(path: Option<String>) -> Result<(), Error> {
    let vault_path = handle_vault_path_argument(path)?;
    if vault_path.exists() {
        // TODO(?): add CLI interactivity to override
        return Err(Error::WalletError(format!(
            "Cannot init vault at {:?}, the directory already exists!",
            vault_path
        )));
    }
    // Generate mnemonic phrase
    let mnemonic = generate_mnemonic_phrase(&mut rand::thread_rng(), 24)?;
    // Encrypt and store it
    let mnemonic_bytes: Vec<u8> = mnemonic.bytes().collect();
    let password = request_new_password();

    eth_keystore::encrypt_key(
        &vault_path,
        &mut rand::thread_rng(),
        mnemonic_bytes,
        &password,
        Some(".wallet"),
    )
    .unwrap_or_else(|error| {
        panic!(
            "Cannot create eth_keystore at {:?}: {:?}",
            vault_path, error
        )
    });
    // Print to an alternate screen, so the mnemonic phrase isn't printed to the terminal.
    let mut screen = AlternateScreen::from(std::io::stdout());
    writeln!(screen, "Wallet mnemonic phrase: {}\n", mnemonic)?;
    screen.flush()?;
    println!("### Do not share or lose this mnemonic phrase! Press any key to complete. ###");
    wait_for_keypress();
    Ok(())
}
