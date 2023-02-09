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

### Initialize

Before creating accounts and signing transactions with them you need to initialize a new HD wallet. To do so:

```sh
forc-wallet init
```

This will require a password for encyrpting the wallet. After the initialization is done you will be given the mnemonic phrase of the wallet.

You can also initialize a wallet with your existing mnemonic phrase by using `forc-wallet import`.

### Create an account

To create an account for the initialized wallet, you can run:

```sh
forc-wallet new
```

This will require your wallet password (the one that you choosed in the initialization step). This will always derive the next account.

### Sign a transaction

To sign a transaction, you need to have the transaction ID. You can generate a transaction and get its ID using `forc-client`. Signing the transaction once you have the ID is simple:

```sh
forc-wallet sign --id <transaction_id> --account-index <account_index>
```

## Other useful commands

### List accounts

To list all accounts derived so far:

```sh
forc-wallet list
```

### Get address of an account

To retrieve the address of a specific account, you can use:

```sh
forc-wallet account --account-index <account_index>
```

### Get private key of an account

To retrieve the private key of a specific account, you can use:

```sh
forc-wallet export --account-index <account_index>
```

### Initialize from existing mnemonic phrase

To initialize a new HD wallet from an existing mnemonic phrase:

```sh
forc-wallet import
```
