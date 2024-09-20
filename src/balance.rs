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
use url::Url;

use crate::{
    account::{
        derive_account, derive_and_cache_addresses, print_balance, print_balance_empty,
        read_cached_addresses, verify_address_and_update_cache,
    },
    format::List,
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
pub type AccountsMap = BTreeMap<usize, fuel_types::Address>;

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
            let addr_bech32 = Bech32Address::from(*addr);
            let account = derive_account(wallet_path, ix, &password)?;
            if verify_address_and_update_cache(
                ix,
                &account,
                &addr_bech32,
                &wallet.crypto.ciphertext,
            )? {
                *addr = account.address().clone().into();
            }
        }
    }

    Ok(addresses)
}

/// Returns N derived addresses. If the `unverified` flag is set, it will not verify the addresses
/// and will use the cached ones.
///
/// This function will override / fix the cached addresses if the user password is requested
pub fn get_derived_accounts(
    wallet_path: &Path,
    unverified: bool,
    target_accounts: Option<usize>,
) -> Result<AccountsMap> {
    let wallet = load_wallet(wallet_path)?;
    let addresses = if unverified {
        read_cached_addresses(&wallet.crypto.ciphertext)?
    } else {
        BTreeMap::new()
    };
    let target_accounts = target_accounts.unwrap_or(1);

    if !unverified || addresses.len() < target_accounts {
        let prompt = "Please enter your wallet password to verify accounts: ";
        let password = rpassword::prompt_password(prompt)?;
        let phrase_recovered = eth_keystore::decrypt_key(wallet_path, password)?;
        let phrase = String::from_utf8(phrase_recovered)?;

        let range = 0..max(target_accounts, DEFAULT_CACHE_ACCOUNTS);
        derive_and_cache_addresses(&wallet, &phrase, range)
    } else {
        Ok(addresses)
    }
}

/// Print collected account balances for each asset type.
pub fn print_account_balances(accounts_map: &AccountsMap, account_balances: &AccountBalances) {
    let mut list = List::default();
    list.add_newline();
    for (ix, balance) in accounts_map.keys().zip(account_balances) {
        let balance: BTreeMap<_, _> = balance
            .iter()
            .map(|(id, &val)| (id.clone(), u128::from(val)))
            .collect();
        if balance.is_empty() {
            continue;
        }

        list.add_seperator();
        list.add(format!("Account {ix}"), accounts_map[ix].to_string());
        list.add_newline();

        for (asset_id, amount) in balance {
            list.add("Asset ID", asset_id);
            list.add("Amount", amount.to_string());
        }
        list.add_seperator();
    }
    println!("{}", list);
}

pub(crate) async fn list_account_balances(
    node_url: &Url,
    addresses: &BTreeMap<usize, fuel_types::Address>,
) -> Result<(Vec<HashMap<String, u64>>, BTreeMap<String, u128>)> {
    println!("Connecting to {node_url}");
    let provider = Provider::connect(&node_url).await?;
    println!("Fetching and summing balances of the following accounts:");
    for (ix, addr) in addresses {
        println!("  {ix:>3}: {addr}");
    }
    let accounts: Vec<_> = addresses
        .values()
        .map(|addr| Wallet::from_address((*addr).into(), Some(provider.clone())))
        .collect();
    let account_balances =
        futures::future::try_join_all(accounts.iter().map(|acc| acc.get_balances())).await?;

    let mut total_balance = BTreeMap::default();
    for acc_bal in &account_balances {
        for (asset_id, amt) in acc_bal {
            let entry = total_balance.entry(asset_id.clone()).or_insert(0u128);
            *entry = entry.checked_add(u128::from(*amt)).ok_or_else(|| {
                anyhow!("Failed to display balance for asset {asset_id}: Value out of range.")
            })?;
        }
    }

    Ok((account_balances, total_balance))
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
    let (account_balances, total_balance) = list_account_balances(node_url, &addresses).await?;

    if balance.accounts {
        print_account_balances(&addresses, &account_balances);
    }

    println!("\nTotal:");
    if total_balance.is_empty() {
        print_balance_empty(&balance.account.node_url);
    } else {
        print_balance(&total_balance);
    }
    Ok(())
}
