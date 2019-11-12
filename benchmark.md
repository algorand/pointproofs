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
