use anyhow::Result;
use testcfg::ForcWalletState;
pub mod testcfg;

#[test]
fn new_creates_accounts_by_default() -> Result<()> {
    testcfg::setup(ForcWalletState::Initialized, &|cfg| {
        let output = cfg.exec(&["accounts", "--unverified"]);

        let expected = "Account addresses (unverified, printed from cache):\n[0]";
        let output_stdout = output.stdout;
        dbg!(&output_stdout);
        let success = output_stdout.starts_with(expected);
        assert!(success)
    })?;
    Ok(())
}