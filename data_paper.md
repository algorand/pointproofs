# data
* dimension = 1000
* proofs in G1
* AWS with Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30 GHz 

## Commit/verify

|operation | cost|
|:---|---:|
| commit_new | 54.34 ms|
| proof_new | 54.41 ms |
| 8_new_proof_without_aggregation | 390.62 ms |
| 8_new_proof_with_aggregation | 280.09 ms |
| 16_new_proof_with_aggregation | 509.03 ms |
| 32_new_proof_with_aggregation | 946.87 ms |
| 64_new_proof_with_aggregation | 1.77 s |
| 128_new_proof_with_aggregation | 3.34 s |
| single commit 8 proof aggregate | 1.55 ms |
| verification (with proof deserialize) |  4.69 ms |
| commit update | 0.31 ms |
| commit batch update 8 values | 1.58 ms |


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
