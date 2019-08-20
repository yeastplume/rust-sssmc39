[![Build Status](https://dev.azure.com/yeastplume/rust-sssmc39/_apis/build/status/yeastplume.rust-sssmc39?branchName=master)](https://dev.azure.com/yeastplume/rust-sssmc39/_build/latest?definitionId=1&branchname=master)

# rust-sssmc39
> "I think Shamir Secret Sharing (and a number of other things, RNGs for example), suffer from a property where they are just complex enough that people are excited to implement them often for little good reason, and then they are complex enough (or have few enough reasons to invest significant time) they implement them poorly." *-Gregory Maxwell*

> "Hold my vodka" *-Yeastplume*

This is a currently very work-in-progress Rust implementation of [SLIP-0039: Shamir's Secret Sharing for Mnemonic Codes](https://github.com/satoshilabs/slips/blob/master/slip-0039.md). It is being developed for eventual incorpration into [Grin's Wallet](https://github.com/mimblewimble/grin-wallet), however I hope it can be of use to anyone looking to implement a master-secret sharing scheme. The specification doesn't just operate on BIP-39 Mnemonics, but can also split keys of almost any size so it should be useful for a wide variety of needs.

Again, this is an untested work-in-progess, so use at your own risk.

## Status

* Field arithmetic, underlying encryption and RS1024 code in place.
* Share splitting, conversion of share to Mnemonic and back in place.
* Secret recovery from share mnemonics in place
* Test vectors from original python reference implementation passing (see below)
* Main master secret to group mnemonics in place (see test in `src/lib.rs`)

## Still Outstanding

* Tightening of certain areas of code (check TODOS)
* API shaping
* Documentation
* Continuous Integration
* Community reviews and Some level of code audit
* Publishing

## Credits

The code was put together using the [SLIP-0039 Python Reference Implementation](https://github.com/trezor/python-shamir-mnemonic/) as a reference

Field arithmetic code taken with thanks and respect from [Rusty Secrets](https://github.com/SpinResearch/RustySecrets), with license details in all derived source files.

Rusty Secrets was forked off [sellibitze's secretshare.](https://github.com/sellibitze/secretshare)
