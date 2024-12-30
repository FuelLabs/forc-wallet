pub mod account;
pub mod balance;
pub mod export;
pub mod format;
pub mod import;
pub mod list;
pub mod new;
pub mod sign;
pub mod utils;

pub const DEFAULT_CACHE_ACCOUNTS: usize = 1;

/// The default network used in the case that none is specified.
pub mod network {
    pub const DEFAULT: &str = MAINNET;
    pub const BETA_2: &str = "https://node-beta-2.fuel.network";
    pub const BETA_2_FAUCET: &str = "https://faucet-beta-2.fuel.network";
    pub const BETA_3: &str = "https://beta-3.fuel.network/";
    pub const BETA_3_FAUCET: &str = "https://faucet-beta-3.fuel.network/";
    pub const BETA_4: &str = "https://beta-4.fuel.network/";
    pub const BETA_4_FAUCET: &str = "https://faucet-beta-4.fuel.network/";
    pub const BETA_5: &str = "https://beta-5.fuel.network/";
    pub const BETA_5_FAUCET: &str = "https://faucet-beta-5.fuel.network/";
    pub const TESTNET: &str = "https://testnet.fuel.network/";
    pub const TESTNET_FAUCET: &str = "https://faucet-testnet.fuel.network/";
    pub const MAINNET: &str = "https://mainnet.fuel.network/";
}

/// Contains definitions of URLs to the block explorer for each network.
pub mod explorer {
    pub const DEFAULT: &str = MAINNET;
    pub const BETA_2: &str = "https://fuellabs.github.io/block-explorer-v2/beta-2";
    pub const BETA_3: &str = "https://fuellabs.github.io/block-explorer-v2/beta-3";
    pub const BETA_4: &str = "https://fuellabs.github.io/block-explorer-v2/beta-4";
    pub const BETA_5: &str = "https://fuellabs.github.io/block-explorer-v2/beta-5";
    pub const TESTNET: &str = "https://app-testnet.fuel.network";
    pub const MAINNET: &str = "https://app.fuel.network";
}
