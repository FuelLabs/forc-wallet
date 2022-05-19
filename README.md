forc-wallet
===

A forc plugin for managing Fuel wallets.

## Instructions

```shell
cargo run -- --help
```

```
USAGE:
    forc-wallet [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -h, --help            Print help information
    -o, --format <FMT>    [default: json] [possible values: json, toml]
    -V, --version         Print version information

SUBCOMMANDS:
    help      Print this message or the help of the given subcommand(s)
    import    Import a wallet from mnemonic phrase
    list      Lists all wallets stored in ~/.fuel/wallets/
    new       Randomly generate a new wallet. By default, wallets are stored in ~/.fuel/wallets/
```
