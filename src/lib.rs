pub mod account;
pub mod balance;
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
    pub const TESTNET: &str = "https://testnet.fuel.network/";
    pub const TESTNET_FAUCET: &str = "https://faucet-testnet.fuel.network/";
    pub const MAINNET: &str = "https://mainnet.fuel.network/";
}

/// Contains definitions of URLs to the block explorer for each network.
pub mod explorer {
    pub const DEFAULT: &str = MAINNET;
    pub const TESTNET: &str = "https://app-testnet.fuel.network";
    pub const MAINNET: &str = "https://app.fuel.network";
}
