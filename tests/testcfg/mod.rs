use anyhow::Result;
use forc_wallet::{new::new_wallet, DEFAULT_CACHE_ACCOUNTS};
use lazy_static::lazy_static;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};
use tempfile::tempdir;

/// Default password to use while creating a wallet.
const DEFAULT_PASSWORD: &str = "1234";

pub enum ForcWalletState {
    /// Wallet is not initialized yet. No wallet file is present at the target folder.
    NotInitialized,
    /// A wallet is initialized, by default we need to have at least `DEFAULT_CACHE_ACCOUNTS` accounts derived.
    Initialized,
}

#[derive(Debug)]
pub struct TestOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: ExitStatus,
}

#[derive(Debug)]
pub struct TestCfg {
    /// The path to the test environment's forc-wallet executable. This should usually be
    /// <TMP_DIR>/forc-wallet. This should be used to execute forc-wallet in the test
    /// environment.
    pub forc_wallet_bin_path: PathBuf,
    /// The path to the test environment's wallet directory. This should usually be
    /// <TMP_DIR>/.forc/wallet/.
    pub wallet_path: PathBuf,
}

lazy_static! {
    static ref WALLET_BINARY_PATH: PathBuf = {
        // Build the binary
        Command::new("cargo")
            .args(&["build", "--bin", "forc-wallet"])
            .status()
            .expect("Failed to build binary");

        // Construct the binary path using CARGO_MANIFEST_DIR
        let manifest_dir = env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is not set");
        let mut binary_path = PathBuf::from(manifest_dir);
        binary_path.push("target");
        binary_path.push("debug");
        binary_path.push("forc-wallet");

        if !binary_path.exists() {
            panic!("Binary not found at {:?}", binary_path);
        }

        binary_path
    };
}

impl TestCfg {
    pub fn new(forc_wallet_bin_path: PathBuf, wallet_path: PathBuf) -> Self {
        Self {
            forc_wallet_bin_path,
            wallet_path,
        }
    }

    /// A function for executing forc wallet with given args at the given path.
    pub fn exec(&mut self, args: &[&str]) -> TestOutput {
        const PROC_NAME: &str = "forc-wallet";
        let output = Command::new(PROC_NAME)
            .args(args)
            .current_dir(&self.forc_wallet_bin_path)
            .output()
            .expect("Failed to execute command");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        TestOutput {
            stdout,
            stderr,
            status: output.status,
        }
    }
}

fn setup_new_wallet(path: &Path) -> Result<()> {
    new_wallet(path, DEFAULT_PASSWORD, DEFAULT_CACHE_ACCOUNTS)?;
    Ok(())
}

fn place_wallet_binary(target_path: &Path) -> Result<()> {
    let wallet_bin = WALLET_BINARY_PATH.to_str().unwrap();

    let target_bin_path = target_path.join("forc-wallet");
    // Create a symlink from the binary to the target path
    #[cfg(target_family = "unix")]
    {
        std::os::unix::fs::symlink(wallet_bin, target_bin_path).expect("Failed to create symlink");
    }

    #[cfg(target_family = "windows")]
    {
        std::os::windows::fs::symlink_file(wallet_bin, target_bin_path)
            .expect("Failed to create symlink");
    }
    Ok(())
}

pub(crate) fn setup(state: ForcWalletState, f: &dyn Fn(&mut TestCfg)) -> Result<()> {
    let testdir = tempdir().unwrap();
    let tmp_home = testdir.path().canonicalize()?;
    let tmp_forc = tmp_home.join(".forc");
    place_wallet_binary(&tmp_home)?;
    fs::create_dir_all(&tmp_forc).unwrap();

    let tmp_forc_wallet_path = tmp_forc.join("wallet");
    match state {
        ForcWalletState::NotInitialized => todo!(),
        ForcWalletState::Initialized => {
            setup_new_wallet(&tmp_forc_wallet_path)?;
        }
    }

    f(&mut TestCfg::new(tmp_home, tmp_forc_wallet_path));
    Ok(())
}
