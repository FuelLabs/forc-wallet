use crate::utils::{derive_account_with_index, DEFAULT_RELATIVE_VAULT_PATH};
use anyhow::Result;
use std::{io::Write, path::PathBuf};
use termion::screen::AlternateScreen;

pub(crate) fn export_account(path: Option<String>, account_index: usize) -> Result<()> {
    let wallet_path = match &path {
        Some(path) => PathBuf::from(path),
        None => home::home_dir().unwrap().join(DEFAULT_RELATIVE_VAULT_PATH),
    };

    let secret_key = derive_account_with_index(&wallet_path, account_index)?;
    let mut screen = AlternateScreen::from(std::io::stdout());
    writeln!(
        screen,
        "Secret key for account {}: {}\n",
        account_index, secret_key
    )?;
    screen.flush()?;
    let mut input = String::new();
    println!("### Press any key to complete. ###");
    std::io::stdin().read_line(&mut input)?;

    Ok(())
}
