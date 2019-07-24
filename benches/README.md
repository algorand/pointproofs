 # Benchmarks on 3.1GHz Intel Core i5 (macOS Mojave 10.14.5)

## Pairing-based scheme

- committing to an n-vector: 80n microseconds
- proving a single element in an n-vector: 80n microseconds
- verifying a single proof: 3600 microseconds (regardless of n)
- updating a proof or a commitment: 220 microseconds no pecomp; 120 microseconds with precomp (regardless of n)

commitments and proofs are 48 bytes

### Room for improvement on individual operations:
- Using a lot more fixed-based precomputation, commit, prove, and both update can each be improved by about 2x
- Verifying cannot be improved much on its own

### Room for improvement via batching:
- Proving for multiple values on a single commitment will cost at most 2x proving for a single value (as long as you produce a single combined proof, which will require all the values to which it refers in order to verify)
- Verifying for multiple values on a single commitment should cost about the same as verifying a single value
- Proofs for multiple values on the same commitment can be combined very cheaply, and will remain 48 bytes
- Proofs for multiple values on different commitments may also be combinable the same way -- need to verify security
- Verifying multiple values on different commitments could save about 2-4x if we do it in a batch rather that separately

### Benchmarking output for the pairing-based scheme

```
Running /Users/reyzin/consulting/algorand/RustProjects/veccom-rust/target/release/deps/pairings-92fd9995499da84f
pairings/commit                            time:   [8.0462 ms 8.0529 ms 8.0611 ms]                           
pairings/prove                             time:   [7.9843 ms 7.9999 ms 8.0257 ms]                          
pairings/verify                            time:   [3.4991 ms 3.7608 ms 4.3201 ms]                          
pairings/commit_update_no_precomp          time:   [213.62 us 214.00 us 214.82 us]
pairings/commit_update_with_precomp        time:   [117.44 us 119.33 us 123.77 us]
pairings/proof_update_no_precomp           time:   [214.27 us 214.60 us 215.24 us]
pairings/proof_update_with_precomp         time:   [118.20 us 118.61 us 119.16 us]
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

