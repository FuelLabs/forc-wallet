use crate::{
    account,
    balance::{self, collect_cached_accounts_or_fill_cache},
};
use anyhow::Result;
use clap::Args;
use std::path::Path;
use url::Url;

#[derive(Debug, Args)]
pub struct List {
    /// The URL of the node to connect to to requests balances.
    #[clap(long, default_value_t = crate::network::DEFAULT.parse().unwrap())]
    pub(crate) node_url: Url,

    /// The minimum amount of derived accounts to display their balances from.
    /// If there are not enough accounts in the cache, the wallet will be unlocked (requesting the
    /// user's password) and will derive more accounts.
    #[clap(short, long)]
    target_accounts: Option<usize>,
}

pub async fn list_wallet_cli(wallet_path: &Path, opts: List) -> Result<()> {
    collect_cached_accounts_or_fill_cache(wallet_path, opts.target_accounts)?;
    balance::cli(
        wallet_path,
        &balance::Balance {
            account: account::Balance {
                node_url: opts.node_url,
                unverified: account::Unverified { unverified: true },
            },
            accounts: true,
        },
    )
    .await
}
