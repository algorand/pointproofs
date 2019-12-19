# veccom-rust


[![Build Status](https://travis-ci.com/algorand/veccom-rust.svg?token=cs332z4omsgc9ykLW8pu&branch=master)](https://travis-ci.com/algorand/veccom-rust)


This is a rust implementation of pairing-based vector commitments over curve bls12-381.

__Dependency__: [Pairing-plus](https://github.com/algorand/pairing-plus)

__Spec__: [Here](https://github.com/algorand/veccom-rust/blob/master/SPEC.md)

__Use this library directly__
* Install rust and cargo toolchain
* Build library: `cargo build --release`
* Run example: `cargo run`
* Run tests: `cargo test [-- --ignore] [--release]`
* Benchmark: `cargo bench`
* Documentation: `cargo doc --open`

__C wrapper__
* generate the header: `make`
* test C wrapper: `make test`

__Go bindings (not working)__
* `go test -v . -run=. -bench=.`
