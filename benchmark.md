# benchmark results on vector commitment scheme

## basics

| Function | Timing |
|---|---:|
| g1_mul             |    0.237 ms |
| g2_mul             |     0.841 ms |
| pairing            |   1.931 ms |


## Parameter Generation
Check `veccom-paramgen`

## Commit


|Function| n = 512 | n = 1024 | main cost |
|---|---:|---:|:---|
| new commitment without pre-computation | 19.6 ms |  35.9 ms | sum of n product |
| new commitment with pre-computation = 3 | 19.6 ms |   35.5 ms | sum of n product |
| new commitment with pre-computation = 256 | 14.4 ms |  32.0 ms | sum of n product |
| commitment update without pre-computation | 0.2 ms| 0.2 ms| 2 hash_to_field + g1_mul |
| commitment update with pre-computation = 3 | 0.1 ms| 0.1 ms| 2 hash_to_field + g1_mul |
| commitment update with pre-computation = 256 | 0.05 ms| 0.05 ms| 2 hash_to_field + g1_mul |

## Proof

|Function| n = 512 | n = 1024 | main cost |
|---|---:|---:|:---|
| new proof without pre-computation | 19.6 ms|  34.7 ms |  sum of n product |
| new proof with pre-computation = 3 | 19.9 ms|   34.6 ms | sum of n product |
| new proof with pre-computation = 256 | 16.6 ms |  34.0 ms |  sum of n product |
| proof update without pre-computation | 0.2 ms| 0.2 ms| hash_to_field + g1_mul |
| proof update with pre-computation = 3 | 0.1 ms| 0.1 ms| hash_to_field + g1_mul |
| proof update with pre-computation = 256 | 0.05 ms| 0.05 ms| hash_to_field + g1_mul |

## Verify

|Function| n = 512 | n = 1024 | main cost |
|---|---:|---:|---:|
|Verify| 3.1 ms| 3.1 ms| hash_to_field + 2 g1_mul + pairing_product |

## aggregation

| Function| 128 scalars |  256 scalars |  512 scalars | 1024 scalars |
|---|---:|---:|---:|---:|
| hash to scalars | 2.98 ms|  10.4 ms | 39.2 ms | 156.7 ms |
| new hash to scalars | 0.6 ms|  1.2 ms | 2.5 ms | 5.3 ms |



| Function| n = 512 | n = 1024 | main cost |
|---|---:|---:|:---|
| aggregate 128 proofs | 8.1 ms | 8.1 ms| hash to 128 scalars + sum of 128 product in G1|
| aggregate 256 proofs | 14.3 ms | 14.4 ms|  hash to 256 scalars + sum of 256 product in G1|
| aggregate n proofs | 25.9 ms | 46.4 ms| hash to n scalars + sum of n product in G1|
| batch verify 128 proofs | 25.7 ms | 25.3 ms| hash to 128 scalars + sum of 128 product in G2|
| batch verify 256 proofs | 42.9 ms | 42.8 ms| hash to 256 scalars + sum of 256 product in G2|
| batch verify n proofs | 71.9 ms | 119.4 ms| hash to n scalars +sum of n product in G2|



## new benchmark data

Cross commit, AWS Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz (Slower than MBP)

### Aggregate, n = 16, data in _ms_


|# commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|
| 2 | 2.25 | 2.95 | 4.13 | 6.22 |
| 4 | 4.12 | 5.56 | 7.98 | 12.06 |
| 8 | 7.65 | 10.54 | 15.40 | 23.55 |
| 16 | 14.69 | 20.59 | 30.04 | 46.65 |
| 32 | 28.67 | 40.38 | 59.11 | 92.28 |
| 64 | 55.96 | 79.02 | | |

### Batch verify, n = 16, data in _ms_


|# commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|
| 2 | 9.17 | 11.43 | 15.00 | 20.95 |
| 4 | 15.01 | 19.87 | 26.69 | 38.72 |
| 8 | 26.68 | 35.89 | 49.98 |  73.58 |
| 16 | 50.54 | 68.21 | 96.42 | 143.25 |
| 32 | 98.27 | 133.59 | 188.95 | 283.71 |
| 64 | 192.22 | | | |


### Aggregate, n = 1024, data in _s_


|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|---:|
| 1024 | 0.098 | 0.85 | 1.23 | 1.82 | 2.89 |

### Batch verify, n = 1024, data in _s_


|# commit | 1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|---:|
| 1024 | 1.99 | 3.07 | 4.23 | 6.00 | |
