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


|Function| n = 512 | n = 1024 |
|---|---:|---:|---:|
| new commitment without pre-computation | 19.6 ms |  35.1 ms | sum of n product |
| new commitment with pre-computation = 3 | 19.6 ms |   35.2 ms | sum of n product |
| new commitment with pre-computation = 256 | 14.4 ms |  34.0 ms | sum of n product |
| commitment update without pre-computation | 0.2 ms| 0.2 ms| 2 hash_to_field + g1_mul |
| commitment update with pre-computation = 3 | 0.1 ms| 0.1 ms| 2 hash_to_field + g1_mul |
| commitment update with pre-computation = 256 | 0.05 ms| 0.05 ms| 2 hash_to_field + g1_mul |

## Proof

|Function| n = 512 | n = 1024 | main cost |
|---|---:|---:|---:|
| new proof without pre-computation | 19.6 ms|  35.1 ms |  sum of n product |
| new proof with pre-computation = 3 | 19.9 ms|   36.0 ms | sum of n product |
| new proof with pre-computation = 256 | 16.6 ms |  33.5 ms |  sum of n product |
| proof update without pre-computation | 0.2 ms| 0.2 ms| hash_to_field + g1_mul |
| proof update with pre-computation = 3 | 0.1 ms| 0.1 ms| hash_to_field + g1_mul |
| proof update with pre-computation = 256 | 0.05 ms| 0.05 ms| hash_to_field + g1_mul |

## Verify

|Function| n = 512 | n = 1024 | main cost |
|---|---:|---:|---:|
|Verify| 3.1 ms| 3.1 ms| hash_to_field + 2 g1_mul + pairing_product |

## aggregation

| Function| n = 512 | n = 1024 | main cost |
|---|---:|---:|---:|
| hash to 128 scalars | 2.82 ms|2.98 ms|  128 hash_to_field  |
| hash to 256 scalars | 9.95 ms|10.65 ms| 256 hash_to_field (with longer inputs)|
| aggregate 128 proofs | 32.4 ms | 33.4 ms| 128 g1_mul|
| aggregate 256 proofs | 69.6 ms | 69.3 ms|  256 g1_mul|
| aggregate n proofs | 154.0 ms | 395.6 ms| n g1_mul |
| batch verify 128 proofs | 103.8 ms | 108.4 ms| 128 g2_mul|
| batch verify 256 proofs | 210.8 ms | 214.8 ms| 256 g2_mul|
| batch verify n proofs | 431.6 ms | 973.0 ms| n g2_mul|
