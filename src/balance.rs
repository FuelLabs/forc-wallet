use anyhow::{anyhow, Result};
use clap::Args;
use fuels::{
    accounts::{wallet::Wallet, ViewOnlyAccount},
    prelude::*,
};
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
    path::Path,
};

use crate::{
    account::{
        derive_account, derive_and_cache_addresses, print_balance, print_balance_empty,
        read_cached_addresses, verify_address_and_update_cache,
    },
    utils::load_wallet,
    DEFAULT_CACHE_ACCOUNTS,
};

#[derive(Debug, Args)]
#[group(skip)]
pub struct Balance {
    // Account-specific args.
    #[clap(flatten)]
    pub(crate) account: crate::account::Balance,
    /// Show the balance for each individual non-empty account before showing
    /// the total.
    #[clap(long)]
    pub(crate) accounts: bool,
}

/// Whether to verify cached accounts or not.
///
/// To verify cached accounts we require wallet vault password.
pub enum AccountVerification {
    No,
    Yes(String),
}

/// List of accounts and amount of tokens they hold with different ASSET_IDs.
pub type AccountBalances = Vec<HashMap<String, u64>>;
/// A mapping between account index and the bech32 address for that account.
pub type AccountsMap = BTreeMap<usize, Bech32Address>;

/// Return a map of accounts after desired verification applied in a map where each key is account
/// index and each value is the `Bech32Address` of that account.
pub fn collect_accounts_with_verification(
    wallet_path: &Path,
    verification: AccountVerification,
) -> Result<AccountsMap> {
    let wallet = load_wallet(wallet_path)?;
    let mut addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
    if let AccountVerification::Yes(password) = verification {
        for (&ix, addr) in addresses.iter_mut() {
            let account = derive_account(wallet_path, ix, &password)?;
            if verify_address_and_update_cache(ix, &account, addr, &wallet.crypto.ciphertext)? {
                *addr = account.address().clone();
            }
        }
    }

    Ok(addresses)
}

/// Select accounts from the cache and if the cache is empty, requests for the user password to
/// unlock the wallet and fill the cache with a default number of addresses.
/// If target_accounts is provided, that is the minimum number of accounts that should be returned.
pub fn collect_cached_accounts_or_fill_cache(
    wallet_path: &Path,
    target_accounts: Option<usize>,
) -> Result<AccountsMap> {
    let wallet = load_wallet(wallet_path)?;
    let addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
    let target_accounts = target_accounts.unwrap_or(1);

    Ok(if addresses.len() < target_accounts {
        let prompt = "Please enter your wallet password to verify accounts: ";
        let password = rpassword::prompt_password(prompt)?;
        let phrase_recovered = eth_keystore::decrypt_key(wallet_path, password)?;
        let phrase = String::from_utf8(phrase_recovered)?;

        let range = addresses.len()..max(target_accounts, DEFAULT_CACHE_ACCOUNTS);
        derive_and_cache_addresses(&wallet, &phrase, range)?;
        read_cached_addresses(&wallet.crypto.ciphertext)?
    } else {
        addresses
    })
}

/// Print collected account balances for each asset type.
pub fn print_account_balances(accounts_map: &AccountsMap, account_balances: &AccountBalances) {
    for (ix, balance) in accounts_map.keys().zip(account_balances) {
        let balance: BTreeMap<_, _> = balance
            .iter()
            .map(|(id, &val)| (id.clone(), u128::from(val)))
            .collect();
        if balance.is_empty() {
            continue;
        }
        println!("\nAccount {ix} -- {}:", accounts_map[ix]);
        print_balance(&balance);
    }
}
pub async fn cli(wallet_path: &Path, balance: &Balance) -> Result<()> {
    let verification = if !balance.account.unverified.unverified {
        let prompt = "Please enter your wallet password to verify accounts: ";
        let password = rpassword::prompt_password(prompt)?;
        AccountVerification::Yes(password)
    } else {
        AccountVerification::No
    };
    let addresses = collect_accounts_with_verification(wallet_path, verification)?;

    let node_url = &balance.account.node_url;
    println!("Connecting to {node_url}");
    let provider = Provider::connect(node_url).await?;
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
        print_account_balances(&addresses, &account_balances);
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
