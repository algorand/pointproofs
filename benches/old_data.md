 # Benchmarks on 3.1GHz Intel Core i5 (macOS Mojave 10.14.5)

__See [here](https://github.com/algorand/pointproofs/blob/master/benchmark.md) for an updated results of data__

## Pairing-based scheme

- committing to an n-vector: 41n microseconds without precomputation (for n=1000 -- not exactly linear), 32n microseconds with precomputation ((256)x(48 n) bytes stored)
- proving a single element in an n-vector: 41n microseconds without precomputation (for n=1000 -- not exactly linear), 33n microseconds with precomputation ((512)x(48 n) bytes stored)
- verifying a single proof (regardless of n): 3450 microseconds
- updating a proof or a commitment (regardless of n): 213 microseconds no pecomp; 116 microseconds with small precomp (6 x (48 n) bytes stored); 56 microseconds with large precomp ((512)x(48 n) bytes stored)

commitments and proofs are 48 bytes

### Room for improvement on individual operations:
- Not much left, except improving the underlying EC and pairing operations

### Room for improvement via batching:
- Proving for multiple values on a single commitment will cost at most 2x proving for a single value (as long as you produce a single combined proof, which will require all the values to which it refers in order to verify)
- Verifying for multiple values on a single commitment should cost about the same as verifying a single value
- Proofs for multiple values on the same commitment can be combined very cheaply, and will remain 48 bytes
- Proofs for multiple values on different commitments may also be combinable the same way -- need to verify security
- Verifying multiple values on different commitments could save about 2-4x if we do it in a batch rather that separately
- Updates to commitments and updates can be batched, which could save us 2-4x

### Benchmarking output for the pairing-based scheme

```
Running /Users/reyzin/consulting/algorand/RustProjects/veccom-rust/target/release/deps/pairings-92fd9995499da84f
pairings/commit_no_precomp         time:   [40.572 ms 40.746 ms 40.933 ms]
pairings/commit_precomp_256        time:   [33.805 ms 33.944 ms 34.116 ms]
pairings/prove_no_precomp          time:   [40.725 ms 41.013 ms 41.311 ms]
pairings/prove_precomp_256         time:   [34.320 ms 34.804 ms 35.913 ms]
pairings/verify                    time:   [3.4856 ms 3.5197 ms 3.5768 ms]                        
pairings/commit_update_no_precomp  time:   [212.30 us 213.43 us 214.81 us]
pairings/commit_update_precomp_3   time:   [116.03 us 116.97 us 120.22 us]
pairings/commit_update_precomp_256 time:   [56.226 us 57.003 us 58.482 us]
pairings/proof_update_no_precomp   time:   [213.27 us 216.24 us 219.22 us]
pairings/proof_update_precomp_3    time:   [113.14 us 113.61 us 114.62 us]
pairings/proof_update_precomp_256  time:   [54.065 us 54.775 us 56.730 us]
```

## Merkle-based scheme

- committing to an n-vector: 1.2*n microseconds
- proving a single element in an n-vector: once commitment is done, essentially free
- verifying a single proof: 8 microseconds (for n = 1000)
- updating a proof: 6 microseconds (for n = 1000)
- updating a commitment: 8 microseconds (for n = 1000)

commitments are 32 bytes long; and proofs are 32 * log_2 n bytes

### Room for improvement via batching:

If enough proofs within the same tree are batched, total length goes down (realistic to see about 2x savings) and total verification times goes down by about the same factor


### Benchmarking output for the Merkle-based scheme
```
test bench_com_merkle                      ... bench:   1,171,284 ns/iter (+/- 16,755)
test bench_commit_update_merkle            ... bench:       7,975 ns/iter (+/- 95)
test bench_proof_update_no_helper_merkle   ... bench:       6,038 ns/iter (+/- 67)
test bench_proof_update_with_helper_merkle ... bench:          16 ns/iter (+/- 2)
test bench_prove_from_scratch_merkle       ... bench:   1,163,089 ns/iter (+/- 9,569)
test bench_prove_from_tree_merkle          ... bench:         154 ns/iter (+/- 9)
test bench_tree_building_merkle            ... bench:   1,265,566 ns/iter (+/- 14,839)
test bench_tree_update_merkle              ... bench:       7,795 ns/iter (+/- 133)
test bench_verify_merkle                   ... bench:       7,829 ns/iter (+/- 82)
```
