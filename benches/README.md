# Benchmarks on 3.1GHz Intel Core i5 (macOS Mojave 10.14.5)

## Pairing-based scheme

- committing to an n-vector: 80n microseconds
- proving a single element in an n-vector: 80n microseconds
- verifying a single proof: 3600 microseconds (regardless of n)
- updating a proof: 220 microseconds (regardless of n)
- updating a commitment: 220 microseconds (regardless of n)

commitments and proofs are 48 bytes

### Room for improvement on individual operations:
- Using fixed-based precomputation, commit, prove, and both update can each be improved by about 2x
- Verifying cannot be improved much on its own

### Room for improvement via batching:
- Proving for multiple values on a single commitment will cost at most 2x proving for a single value (as long as you produce a single combined proof, which will require all the values to which it refers in order to verify)
- Verifying for multiple values on a single commitment should cost about the same as verifying a single value
- Proofs for multiple values on the same commitment can be combined very cheaply, and will remain 48 bytes
- Verifying multiple values on different commitments could save about 2x if we do it in a batch rather that separately

### Benchmarking output for the pairing-based scheme

```
Running /Users/reyzin/consulting/algorand/RustProjects/veccom-rust/target/release/deps/pairings-92fd9995499da84f
Benchmarking pairings/commit: Collecting 10 samples in estimated 5.2539 s (275 iteration                                                                                        pairings/commit         time:   [8.1664 ms 8.2280 ms 8.3016 ms]
Benchmarking pairings/prove: Collecting 10 samples in estimated 5.1990 s (275 iterations                                                                                        pairings/prove          time:   [8.1159 ms 8.1602 ms 8.2839 ms]
1 (10.00%) high severe
Benchmarking pairings/verify: Collecting 10 samples in estimated 34.548 s (55 iterations                                                                                        pairings/verify         time:   [3.5142 ms 3.5523 ms 3.5953 ms]
Benchmarking pairings/commit_update: Collecting 10 samples in estimated 5.0579 s (1265 i                                                                                        pairings/commit_update  time:   [214.95 us 216.72 us 218.16 us]
1 (10.00%) high severe
Benchmarking pairings/proof_update: Collecting 10 samples in estimated 33.961 s (55 iter                                                                                        pairings/proof_update   time:   [215.34 us 216.03 us 217.71 us]

```

## Merkle-based scheme

- committing to an n-vector: 1.2*n microseconds
- proving a single element in an n-vector: once commitment is done, essentially free (though in the current implementation we don't cache enough data and recomput each proof from scratch -- this should be fixed)
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

