# veccom-rust

This is a rust implementation of pairing-based vector commitments over curve bls12-381.

__Dependency__: [Pairing-fork](https://github.com/algorand/pairing-fork)

__Spec__: to be developed

__Use this library directly__
* Install rust and cargo toolchain
** In particular, the test package requires installing nightly: `rustup install nightly` and then pass `+nightly` to `cargo`
* Build library: `cargo build --release`
* Run example: `cargo run`

__Go bindings__
* `GODEBUG=cgocheck=0 go test -v .`
