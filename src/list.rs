use crate::{
    account::{print_balance, print_balance_empty, Unverified},
    balance::{get_derived_accounts, list_account_balances, print_account_balances},
};
use anyhow::Result;
use clap::Args;
use std::{collections::BTreeMap, path::Path};
use url::Url;

#[derive(Debug, Args)]
pub struct List {
    /// The URL of the node to connect to to requests balances.
    #[clap(long, default_value_t = crate::network::DEFAULT.parse().unwrap())]
    pub(crate) node_url: Url,

    /// Contains optional flag for displaying all accounts as hex / bytes values.
    ///
    /// pass in --as-hex for this alternative display.
    #[clap(flatten)]
    unverified: Unverified,

    /// The minimum amount of derived accounts to display their balances from.
    /// If there are not enough accounts in the cache, the wallet will be unlocked (requesting the
    /// user's password) and will derive more accounts.
    #[clap(short, long)]
    target_accounts: Option<usize>,
}

pub async fn list_wallet_cli(wallet_path: &Path, opts: List) -> Result<()> {
    let addresses = get_derived_accounts(
        wallet_path,
        opts.unverified.unverified,
        opts.target_accounts,
    )?
    .range(0..opts.target_accounts.unwrap_or(1))
    .map(|(a, b)| (*a, b.clone()))
    .collect::<BTreeMap<_, _>>();

    let (account_balances, total_balance) =
        list_account_balances(&opts.node_url, &addresses).await?;
    print_account_balances(&addresses, &account_balances);
    println!("\nTotal:");
    if total_balance.is_empty() {
        print_balance_empty(&opts.node_url);
    } else {
        print_balance(&total_balance);
    }
    Ok(())
}
