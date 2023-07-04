use anyhow::{anyhow, Result};
use clap::Args;
use fuels::{
    accounts::{wallet::Wallet, ViewOnlyAccount},
    prelude::*,
};
use std::{collections::BTreeMap, path::Path};

use crate::{
    account::{
        derive_account, print_balance, print_balance_empty, read_cached_addresses,
        verify_address_and_update_cache,
    },
    utils::load_wallet,
};

#[derive(Debug, Args)]
pub struct Balance {
    // Account-specific args.
    #[clap(flatten)]
    pub(crate) account: crate::account::Balance,
    /// Show the balance for each individual non-empty account before showing
    /// the total.
    #[clap(long)]
    accounts: bool,
}

pub async fn cli(wallet_path: &Path, balance: &Balance) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;
    let mut addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
    if !balance.account.unverified.unverified {
        let prompt = "Please enter your wallet password to verify accounts: ";
        let password = rpassword::prompt_password(prompt)?;
        for (&ix, addr) in addresses.iter_mut() {
            let account = derive_account(wallet_path, ix, &password)?;
            if verify_address_and_update_cache(ix, &account, addr, &wallet.crypto.ciphertext)? {
                *addr = account.address().clone();
            }
        }
    };
    println!("Connecting to {}", balance.account.node_url);
    let provider = Provider::connect(&balance.account.node_url).await?;
    println!("Fetching and summing balances of the following accounts:");
    for (ix, addr) in &addresses {
        println!("  {ix:>3}: {addr}");
    }
    let accounts: Vec<_> = addresses
        .values()
        .map(|addr| Wallet::from_address(addr.clone(), Some(provider.clone())))
        .collect();
    let account_balances =
        futures::future::try_join_all(accounts.iter().map(|acc| acc.get_balances())).await?;

    if balance.accounts {
        for (ix, balance) in addresses.keys().zip(&account_balances) {
            let balance: BTreeMap<_, _> = balance
                .iter()
                .map(|(id, &val)| (id.clone(), u128::from(val)))
                .collect();
            if balance.is_empty() {
                continue;
            }
            println!("\nAccount {ix}:");
            print_balance(&balance);
        }
    }

    let mut total_balance = BTreeMap::default();
    println!("\nTotal:");
    for acc_bal in account_balances {
        for (asset_id, amt) in acc_bal {
            let entry = total_balance.entry(asset_id.clone()).or_insert(0u128);
            *entry = entry.checked_add(u128::from(amt)).ok_or_else(|| {
                anyhow!("Failed to display balance for asset {asset_id}: Value out of range.")
            })?;
        }
    }
    if total_balance.is_empty() {
        print_balance_empty(&balance.account.node_url);
    } else {
        print_balance(&total_balance);
    }
    Ok(())
}
