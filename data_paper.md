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

## Batch proof generation

|operation | cost|
|---:|---:|
| proof_new | 54.41 ms |
| 8_new_proof_without_aggregation | 390.62 ms |
| 2_new_proof_with_aggregation | 90.88 ms |
| 4_new_proof_with_aggregation | 158.29 ms |
| 8_new_proof_with_aggregation | 280.09 ms |
| 16_new_proof_with_aggregation | 509.03 ms |
| 32_new_proof_with_aggregation | 946.87 ms |
| 64_new_proof_with_aggregation | 1.77 s |
| 128_new_proof_with_aggregation | 3.34 s |
| 256_new_proof_with_aggregation | 6.97 s |
| 512_new_proof_with_aggregation | 19.75 s |

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
|proof_per_commit = 64 |  s |
|proof_per_commit =128 |  s |
|proof_per_commit =256 |  s |
|proof_per_commit =512 |  s |


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
