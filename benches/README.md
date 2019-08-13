 # Benchmarks on 3.1GHz Intel Core i5 (macOS Mojave 10.14.5)

## Pairing-based scheme

- committing to an n-vector: 80n microseconds without precomputation, 32n microseconds with precomputation ((256)x(48 n) bytes stored)
- proving a single element in an n-vector: 80n microseconds without precomputation, 33n microseconds with precomputation ((512)x(48 n) bytes stored)
- verifying a single proof (regardless of n): 3450 microseconds
- updating a proof or a commitment (regardless of n): 213 microseconds no pecomp; 116 microseconds with small precomp (6 x (48 n) bytes stored); 55 microseconds with large precomp ((512)x(48 n) bytes stored)

commitments and proofs are 48 bytes

### Room for improvement on individual operations:
- Not much left, except improving the underlying EC and pairing operations

### Room for improvement via batching:
- Proving for multiple values on a single commitment will cost at most 2x proving for a single value (as long as you produce a single combined proof, which will require all the values to which it refers in order to verify)
- Verifying for multiple values on a single commitment should cost about the same as verifying a single value
- Proofs for multiple values on the same commitment can be combined very cheaply, and will remain 48 bytes
- Proofs for multiple values on different commitments may also be combinable the same way -- need to verify security
- Verifying multiple values on different commitments could save about 2-4x if we do it in a batch rather that separately

### Benchmarking output for the pairing-based scheme

```
Running /Users/reyzin/consulting/algorand/RustProjects/veccom-rust/target/release/deps/pairings-92fd9995499da84f
pairings/commit_no_precomp         time:   [7.9110 ms 7.9502 ms 8.0277 ms]
pairings/commit_precomp_256        time:   [3.1413 ms 3.1602 ms 3.1954 ms]
pairings/prove_no_precomp          time:   [7.8364 ms 7.8440 ms 7.8535 ms]
pairings/prove_precomp_256         time:   [3.2569 ms 3.2793 ms 3.3192 ms]
pairings/verify                    time:   [3.4472 ms 3.4492 ms 3.4515 ms]                        
pairings/commit_update_no_precomp  time:   [211.73 us 212.40 us 213.16 us]
pairings/commit_update_precomp_3   time:   [114.77 us 115.01 us 115.52 us]
pairings/commit_update_precomp_256 time:   [55.347 us 56.253 us 57.737 us]
pairings/proof_update_no_precomp   time:   [212.46 us 213.58 us 216.69 us]
pairings/proof_update_precomp_3    time:   [115.80 us 116.18 us 116.95 us]
pairings/proof_update_precomp_256  time:   [52.763 us 53.511 us 55.652 us]
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

