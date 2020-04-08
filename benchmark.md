# data
* dimension = 1024
* proofs in G1
* AWS with Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30 GHz

## Basic Commit/verify

|operation | cost|
|:---|---:|
| commit_new | 54.34 ms|
| proof_new | 54.41 ms |
| single commit 8 proof aggregate | 1.55 ms |
| verification (with proof deserialize) |  4.69 ms |

## Batch proof generation, sequential
Best case scenario, the input indices are sequential

|operation | cost|
|---:|---:|
| proof_new | 54.41 ms |
| 8_new_proof_without_aggregation | 55.71 ms |
| 2_new_proof_with_aggregation | 55.31 ms |
| 4_new_proof_with_aggregation | 55.43 ms |
| 8_new_proof_with_aggregation | 55.30 ms |
| 16_new_proof_with_aggregation | 56.21 ms |
| 32_new_proof_with_aggregation | 58.23 ms |
| 64_new_proof_with_aggregation | 61.55 ms |
| 128_new_proof_with_aggregation | 67.37 ms |
| 256_new_proof_with_aggregation | 80.29 ms |
| 512_new_proof_with_aggregation | 104.65 ms |

## Batch proof generation, randomized
Average case scenario, the input indices are randomized

|operation | cost|
|---:|---:|
| proof_new | 54.41 ms |
| 2_new_proof_with_aggregation | 67.39 ms |
| 4_new_proof_with_aggregation | 76.82 ms |
| 8_new_proof_with_aggregation | 83.31 ms |
| 16_new_proof_with_aggregation | 87.38 ms |
| 32_new_proof_with_aggregation | 90.28 ms |
| 64_new_proof_with_aggregation | 93.27 ms |
| 128_new_proof_with_aggregation | 97.72 ms |
| 256_new_proof_with_aggregation | 105.87 ms |
| 512_new_proof_with_aggregation | 121.58 ms |

## Commit batch update
|operation | cost|
|:---|---:|
| commit update | 0.31 ms |
| commit update with pre256 | 0.06 ms |
| commit batch update 8 values | 1.58 ms |
| commit batch update 8 values with pre256 | 0.48 ms |

## Single commit batch verify

|# proofs | cost|
|---:|---:|
| 1 proof | 4.72 ms |
| aggregation of   2 proofs | 7.02 ms |
| aggregation of   4 proofs | 8.13 ms |
| aggregation of   8 proofs | 9.86 ms |
| aggregation of  16 proofs | 12.69 ms |
| aggregation of  32 proofs | 17.69 ms |
| aggregation of  64 proofs | 25.55 ms |
| aggregation of 128 proofs | 39.55 ms |
| aggregation of 256 proofs | 63.81 ms |
| aggregation of 512 proofs | 105.76 ms |


## Cross commits batch verify
* Number of commits = 1000

|Proof per commit| cost|
|---:|---:|
|proof_per_commit =  2 | 2.97 s |
|proof_per_commit =  4 | 4.09 s |
|proof_per_commit =  8 | 5.82 s |
|proof_per_commit = 16 | 8.79 s |
|proof_per_commit = 32 | 13.68 s |
|proof_per_commit = 64 | 21.70 s |
|proof_per_commit =128 | 35.69 s |
|proof_per_commit =256 | 60.25 s |
|proof_per_commit =512 | 102.67 s |


## Aggregation
### one proof per commit
| # commits | aggregation | verification (with proof deserialize)|
|:---|---:|---:|
| 10 | 1.91 ms | 22.37 ms |
| 1000 | 70.72 ms| 1.91 s |
| 2000 | 129.19 ms | 3.81 s |
| 3000 | 186.23 ms | 5.71 s |
| 4000 | 242.70 ms | 7.60 s |
| 5000 | 297.37 ms | 9.52 s |


### 8 proofs per commit
| # commits | aggregation | verification (with proof deserialize)|
|:---|---:|---:|
| 10 | 1.97 ms | 61.25 ms |
| 1000 | 72.45 ms| 5.75 s |
| 2000 | 132.58 ms | 11.48 s |
| 3000 | 191.45 ms | 17.24 s |
| 4000 | 249.19 ms | 22.97 s |
| 5000 | 305.37 ms | 28.73 s |
