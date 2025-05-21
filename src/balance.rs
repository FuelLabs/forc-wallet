use crate::{
    DEFAULT_CACHE_ACCOUNTS,
    account::{
        derive_account_unlocked, derive_and_cache_addresses, print_balance, print_balance_empty,
        read_cached_addresses, verify_address_and_update_cache,
    },
    format::List,
    utils::load_wallet,
};
use anyhow::{Result, anyhow};
use clap::Args;
use fuels::{
    accounts::{ViewOnlyAccount, provider::Provider, wallet::Wallet},
    types::{Address, bech32::Bech32Address, checksum_address::checksum_encode},
};
use std::{
    cmp::max,
    collections::{BTreeMap, HashMap},
    path::Path,
};
use url::Url;

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
pub type AccountBalances = Vec<HashMap<String, u128>>;
/// A mapping between account index and the bech32 address for that account.
pub type AccountsMap = BTreeMap<usize, Address>;

/// Return a map of accounts after desired verification applied in a map where each key is account
/// index and each value is the `Bech32Address` of that account.
pub async fn collect_accounts_with_verification(
    wallet_path: &Path,
    verification: AccountVerification,
    node_url: &Url,
) -> Result<AccountsMap> {
    let wallet = load_wallet(wallet_path)?;
    let mut addresses = read_cached_addresses(&wallet.crypto.ciphertext)?;
    if let AccountVerification::Yes(password) = verification {
        for (&ix, addr) in addresses.iter_mut() {
            let addr_bech32 = Bech32Address::from(*addr);
            let provider = Provider::connect(node_url).await?;
            let account = derive_account_unlocked(wallet_path, ix, &password, &provider)?;
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
pub async fn get_derived_accounts(
    ctx: &crate::CliContext,
    unverified: bool,
    target_accounts: Option<usize>,
) -> Result<AccountsMap> {
    let wallet = load_wallet(&ctx.wallet_path)?;
    let addresses = if unverified {
        read_cached_addresses(&wallet.crypto.ciphertext)?
    } else {
        BTreeMap::new()
    };
    let target_accounts = target_accounts.unwrap_or(1);

    if !unverified || addresses.len() < target_accounts {
        let prompt = "Please enter your wallet password to verify accounts: ";
        let password = rpassword::prompt_password(prompt)?;
        let phrase_recovered = eth_keystore::decrypt_key(&ctx.wallet_path, password)?;
        let phrase = String::from_utf8(phrase_recovered)?;

        let range = 0..max(target_accounts, DEFAULT_CACHE_ACCOUNTS);
        derive_and_cache_addresses(ctx, &phrase, range).await
    } else {
        Ok(addresses)
    }
}

/// Print collected account balances for each asset type.
pub fn print_account_balances(
    accounts_map: &AccountsMap,
    account_balances: &AccountBalances,
) -> Result<()> {
    let mut list = List::default();
    list.add_newline();
    for (ix, balance) in accounts_map.keys().zip(account_balances) {
        let balance: BTreeMap<_, _> = balance.iter().map(|(id, &val)| (id.clone(), val)).collect();
        if balance.is_empty() {
            continue;
        }
        list.add_separator();
        list.add(
            format!("Account {ix}"),
            checksum_encode(&format!("0x{}", accounts_map[ix]))?,
        );
        list.add_newline();

        for (asset_id, amount) in balance {
            list.add("Asset ID", asset_id);
            list.add("Amount", amount.to_string());
        }
        list.add_separator();
    }
    println!("{}", list);
    Ok(())
}

pub(crate) async fn list_account_balances(
    node_url: &Url,
    addresses: &BTreeMap<usize, Address>,
) -> Result<(Vec<HashMap<String, u128>>, BTreeMap<String, u128>)> {
    println!("Connecting to {node_url}");
    let provider = Provider::connect(&node_url).await?;
    println!("Fetching and summing balances of the following accounts:");
    for (ix, addr) in addresses {
        let addr = format!("0x{}", addr);
        let checksum_addr = checksum_encode(&addr)?;
        println!("  {ix:>3}: {checksum_addr}");
    }
    let accounts: Vec<_> = addresses
        .values()
        .map(|addr| Wallet::new_locked(Bech32Address::from(*addr), provider.clone()))
        .collect();
    let account_balances =
        futures::future::try_join_all(accounts.iter().map(|acc| acc.get_balances())).await?;

    let mut total_balance = BTreeMap::default();
    for acc_bal in &account_balances {
        for (asset_id, amt) in acc_bal {
            let entry = total_balance.entry(asset_id.clone()).or_insert(0u128);
            *entry = entry.checked_add(*amt).ok_or_else(|| {
                anyhow!("Failed to display balance for asset {asset_id}: Value out of range.")
            })?;
        }
    }

    Ok((account_balances, total_balance))
}

pub async fn cli(ctx: &crate::CliContext, balance: &Balance) -> Result<()> {
    let verification = if !balance.account.unverified.unverified {
        let prompt = "Please enter your wallet password to verify accounts: ";
        let password = rpassword::prompt_password(prompt)?;
        AccountVerification::Yes(password)
    } else {
        AccountVerification::No
    };

    let addresses =
        collect_accounts_with_verification(&ctx.wallet_path, verification, &ctx.node_url).await?;
    let (account_balances, total_balance) =
        list_account_balances(&ctx.node_url, &addresses).await?;

    if balance.accounts {
        print_account_balances(&addresses, &account_balances)?;
    }

    println!("\nTotal:");
    if total_balance.is_empty() {
        print_balance_empty(&ctx.node_url);
    } else {
        print_balance(&total_balance);
    }
    Ok(())
}
