use crate::{
    account::{UnverifiedOpt, print_balance, print_balance_empty},
    balance::{get_derived_accounts, list_account_balances, print_account_balances},
};
use anyhow::Result;
use clap::Args;
use std::collections::BTreeMap;

#[derive(Debug, Args)]
pub struct List {
    /// Contains optional flag for displaying all accounts as hex / bytes values.
    ///
    /// pass in --as-hex for this alternative display.
    #[clap(flatten)]
    unverified: UnverifiedOpt,

    /// The minimum amount of derived accounts to display their balances from.
    /// If there are not enough accounts in the cache, the wallet will be unlocked (requesting the
    /// user's password) and will derive more accounts.
    #[clap(short, long)]
    target_accounts: Option<usize>,
}

pub async fn list_wallet_cli(ctx: &crate::CliContext, opts: List) -> Result<()> {
    let addresses = get_derived_accounts(ctx, opts.unverified.unverified, opts.target_accounts)
        .await?
        .range(0..opts.target_accounts.unwrap_or(1))
        .map(|(a, b)| (*a, *b))
        .collect::<BTreeMap<_, _>>();

    let (account_balances, total_balance) =
        list_account_balances(&ctx.node_url, &addresses).await?;
    print_account_balances(&addresses, &account_balances)?;
    println!("\nTotal:");
    if total_balance.is_empty() {
        print_balance_empty(&ctx.node_url);
    } else {
        print_balance(&total_balance);
    }
    Ok(())
}
