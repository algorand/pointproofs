# veccom-rust


[![Build Status](https://travis-ci.com/algorand/veccom-rust.svg?token=cs332z4omsgc9ykLW8pu&branch=master)](https://travis-ci.com/algorand/veccom-rust)


This is a rust implementation of pairing-based vector commitments over curve bls12-381.

__Dependency__: [Pairing-fork](https://github.com/algorand/pairing-fork)

__Spec__: to be developed

__Use this library directly__
* Install rust and cargo toolchain
* Build library: `cargo build --release`
* Run example: `cargo run`
* Run tests: `cargo test`
* Benchmark: `cargo bench`

__Go bindings__
* `go test -v . -run=. -bench=.`
