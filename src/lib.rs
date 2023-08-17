pub mod account;
pub mod balance;
pub mod import;
pub mod new;
pub mod sign;
pub mod utils;

/// The default network used in the case that none is specified.
pub mod network {
    pub const DEFAULT: &str = BETA_4;
    pub const BETA_2: &str = "https://node-beta-2.fuel.network";
    pub const BETA_2_FAUCET: &str = "https://faucet-beta-2.fuel.network";
    pub const BETA_3: &str = "https://beta-3.fuel.network/";
    pub const BETA_3_FAUCET: &str = "https://faucet-beta-3.fuel.network/";
    pub const BETA_4: &str = "https://beta-4.fuel.network/";
    pub const BETA_4_FAUCET: &str = "https://faucet-beta-4.fuel.network/";
}

/// Contains definitions of URLs to the block explorer for each network.
pub mod explorer {
    pub const DEFAULT: &str = BETA_4;
    pub const BETA_2: &str = "https://fuellabs.github.io/block-explorer-v2/beta-2";
    pub const BETA_3: &str = "https://fuellabs.github.io/block-explorer-v2/beta-3";
    pub const BETA_4: &str = "https://fuellabs.github.io/block-explorer-v2/beta-4";
}
