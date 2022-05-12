forc-wallet
===

A forc plugin for generating or importing wallets using BIP39 phrases.

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
    generate    Randomly generate a new wallet
    help        Print this message or the help of the given subcommand(s)
    import      Import a wallet from mnemonic phrase
```
