# forc-wallet

A forc plugin for managing Fuel wallets.

## Quickstart

### Installation through fuelup (recommended)

`forc-wallet` is packaged alongside the default distributed toolchains when installed using
[fuelup](https://github.com/fuellabs/fuelup). If you have the `latest` toolchain installed,
you should already have `forc-wallet` available:

```console
$ fuelup toolchain install latest
$ forc-wallet --version
forc-wallet 0.1.3
```

For usage in [custom toolchains](https://fuellabs.github.io/fuelup/master/concepts/toolchains.html#custom-toolchains):

```sh
fuelup component add forc-wallet
```

### Installation through cargo

Otherwise, you may use cargo:

```sh
cargo install forc-wallet
```

### Create a wallet

Before creating accounts and signing transactions with them you need to create a wallet. To do so:

```sh
forc-wallet new
```

This will require a password for encrypting the wallet. After the wallet is created you will be shown the mnemonic phrase.

> Note: You will need your password for signing and account derivation, and you will need your mnemonic phrase if you wish to recover your wallet in the future.

### Import a wallet

To import a wallet from an existing mnemonic phrase, use:

```sh
forc-wallet import
```

> Note: `forc-wallet` adheres to the [Web3 Secret Storage Definition](https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage) and accepts paths to wallet files that adhere to this standard.

### Create an account

To create an account for the wallet, you can run:

```sh
forc-wallet account new
```

This will require your wallet password (the one that you chose during creation). This command will always derive the next account that has not yet been derived locally.

To list all accounts derived so far, use the following:

```sh
forc-wallet accounts
```

> Note: When we "create" an account, we are really just *revealing* it. All accounts are derived deterministically based on the wallet's mnemonic phrase and derivation path. `forc-wallet` will cache the public addresses of derived accounts within `~/.fuel/wallets/accounts`.

### Sign a transaction

To sign a transaction, you can do so with its ID. You can generate a transaction and get its ID using `forc-client`. Signing the transaction once you have the ID is simple:

```sh
forc-wallet account <account_index> sign tx-id <transaction_id>
```

### Sign arbitrary data

You may sign a string directly:

```sh
forc-wallet account <account_index> sign string "Blah blah blah"
```

Or the contents of a file:

```sh
forc-wallet account <account_index> sign file <path>
```

You may also sign a hex-encoded byte string:

```sh
forc-wallet account <account_index> sign hex 0x0123456789ABCDEF
```

The hex prefix at the beginning of the string is optional, e.g. the following is the same as above:

```sh
forc-wallet account <account_index> sign hex 0123456789ABCDEF
```

You can also use the `sign` subcommand directly, e.g. the following is the same:

```sh
forc-wallet sign --account <account_index> hex 0123456789ABCDEF
```

Using the `sign` subcommand, you can choose to sign directly with a private key (rather than a wallet account):

```sh
forc-wallet sign --private hex 0123456789ABCDEF
```

## Other useful commands

### Get address of an account

To derive the address of a specific account, you can use:

```sh
forc-wallet account <account_index>
```

### Get private key of an account

To retrieve the private key of a specific account, you can use:

```sh
forc-wallet account <account_index> private-key
```
