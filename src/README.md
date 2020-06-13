
<!--
CREDIT: http://patorjk.com/software/taag
         _____  .__                                          .___
        /  _  \ |  |    ____   ________________    ____    __| _/
       /  /_\  \|  |   / ___\ /  _ \_  __ \__  \  /    \  / __ |
      /    |    \  |__/ /_/  >  <_> )  | \// __ \|   |  \/ /_/ |
      \____|__  /____/\___  / \____/|__|  (____  /___|  /\____ |
            \/     /_____/                   \/     \/      \/

      __________      .__        __                              _____       
      \______   \____ |__| _____/  |______________  ____   _____/ ____\______
       |     ___/  _ \|  |/    \   __\____ \_  __ \/  _ \ /  _ \   __\/  ___/
       |    |  (  <_> )  |   |  \  | |  |_> >  | \(  <_> |  <_> )  |  \___ \
       |____|   \____/|__|___|  /__| |   __/|__|   \____/ \____/|__| /____  >
                              \/     |__|                                 \/
-->


# Pointproofs
[![Build Status](https://travis-ci.com/algorand/pointproofs.svg?branch=master)](https://travis-ci.com/algorand/pointproofs)

This is Algorand's implementation of __Pointproofs: Aggregating Proofs for Multiple Vector Commitments__.
This implementation uses bls12-381 curve.


## Documentation
* [Spec](https://github.com/algorand/pointproofs/blob/master/SPEC.md)
* [Preprint](https://eprint.iacr.org/2020/419).


## Code status

* Version 0.1.
* This code is __NOT__ production-ready yet. It passed two external audits, but additional auditing and testing is required before deployment

## Use this library directly
* Install rust and cargo toolchain
* Build library: `cargo build --release`
* Run example: `cargo run`
* Run tests: `cargo test [-- --ignore] [--release]`
* Benchmark: `cargo bench`
  * see `benches` folder for more options
* Documentation: `cargo doc --open`

## C wrapper
* generate the header: `make`
* test C wrapper: `make test`

## Dependency
* `Pairing-plus` library: [stable](https://crates.io/crates/pairing-plus) [dev](https://github.com/algorand/pairing-plus).
  * A fork of zkcrypto's pairing library; with additional functions such as `hash to groups`
  and performance improvements such as `sum of product`.
* `pointproofs-paramgen`: [stable](TBD) [dev](https://github.com/algorand/pointproofs-paramgen)
  * This crate is used to generate the so called _common reference string_ in an MPC manner.
  * A sample CRS is provided with the code for testing purpose.

## License

MIT


## Citation

``` bibtex
@misc{Algo20,
    author    = {Algorand},
    title     = {Source code for Pointproofs},
    note      = "\url{https://github.com/algorand/pointproofs}",
    year      = {2020},
}
```



## Performance
* dimension = 1024
* AWS with Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30 GHz

|operation | cost|
|:---|---:|
| commit_new | 54.34 ms|
| proof_new | 54.41 ms |
| single commit 8 proof aggregate | 1.55 ms |
| verification (with proof deserialize) |  4.69 ms |


See [here](https://github.com/algorand/pointproofs/blob/master/benchmark.md) for more data.
