# Benchmarks on 3.1GHz Intel Core i5 (macOS Mojave 10.14.5)

## Pairing-based scheme

- committing to an n-vector: 270n microseconds
- proving a single element in an n-vector: 270n microseconds
- verifying a single proof: 3600 microseconds (regardless of n)
- updating a proof: 270 microseconds (regardless of n)
- updating a commitment: 270 microseconds (regardless of n)

commitments and proofs are 48 bytes

### Room for improvement on individual operations:
- Using multi-exponentiation and fixed-based precomputation, commit and prove can each be improved by about 5x-10x
- Using fixed-based precomputation, updating commitments and proofs can be improved by about 2x-4x
- Verifying cannot be improved much -- I'd be surprised if we could get 1.5x improvement

### Room for improvement via batching:
- Proving for multiple values on a single commitment will cost at most 2x proving for a single value (as long as you produce a single combined proof, which will require all the values to which it refers in order to verify)
- Verifying for multiple values on a single commitment should cost about the same as verifying a single value
- Proofs for multiple values on the same commitment can be combined very cheaply, and will remain 48 bytes

### Benchmarking output for the pairing-based scheme

```
     Running /Users/reyzin/consulting/algorand/RustProjects/veccom-rust/target/release/deps/pairings-8433c74c2f0d795d
pairings/commit         time:   [26.800 ms 26.945 ms 27.371 ms]                           
                        change: [+0.0909% +2.6665% +6.3637%] (p = 0.09 > 0.05)
                        No change in performance detected.
Found 2 outliers among 10 measurements (20.00%)
  2 (20.00%) high severe
pairings/prove          time:   [26.530 ms 26.546 ms 26.570 ms]                          
                        change: [-0.6649% -0.2555% +0.0437%] (p = 0.23 > 0.05)
                        No change in performance detected.
pairings/verify         time:   [3.6095 ms 3.6117 ms 3.6133 ms]                          
                        change: [-0.8096% -0.3158% -0.0028%] (p = 0.19 > 0.05)
                        No change in performance detected.
pairings/commit_update  time:   [273.68 us 274.12 us 274.91 us]                                  
                        change: [-0.1691% +0.1597% +0.4692%] (p = 0.36 > 0.05)
                        No change in performance detected.
pairings/proof_update   time:   [270.10 us 271.22 us 273.82 us]                                 
                        change: [-0.1212% +2.2563% +4.7604%] (p = 0.12 > 0.05)
                        No change in performance detected.
Found 2 outliers among 10 measurements (20.00%)
  2 (20.00%) high mild

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

