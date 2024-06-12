use anyhow::Result;
use enigo::{Enigo, Settings};
use std::{thread, time::Duration};
use testcfg::ForcWalletState;

use crate::testcfg::input_utils::enter_password;

pub mod testcfg;

#[test]
#[ignore]
fn new_creates_accounts_by_default() -> Result<()> {
    testcfg::setup(ForcWalletState::Initialized, &|cfg| {
        let output = cfg.exec(&["accounts", "--unverified"], &|| {});

        let expected = "Account addresses (unverified, printed from cache):\n[0]";
        let output_stdout = output.stdout;
        dbg!(&output_stdout);
        let success = output_stdout.starts_with(expected);
        assert!(success)
    })?;
    Ok(())
}

#[test]
fn new_shows_mnemonic() -> Result<()> {
    testcfg::setup(ForcWalletState::NotInitialized, &|cfg| {
        let output = cfg.exec(
            &["--path", &format!("{}", cfg.wallet_path.display()), "new"],
            &|| {
                thread::sleep(Duration::from_millis(1000));
                let mut enigo = Enigo::new(&Settings::default()).unwrap();
                // First password
                enter_password(&mut enigo).unwrap();
                // Verify password
                thread::sleep(Duration::from_millis(100));
                enter_password(&mut enigo).unwrap();
            },
        );

        let expected = "Wallet mnemonic phrase:";
        let output_stdout = output.stdout;
        dbg!(&output_stdout);
        let success = output_stdout.contains(expected);
        assert!(success)
    })?;
    Ok(())
}
