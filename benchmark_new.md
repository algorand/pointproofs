# benchmark results on vector commitment scheme

__To be completed.__
## Setup

* AWS Intel(R) Xeon(R) CPU E5-2686 v4 @ __2.30__ GHz (Slower than MBP).
* Public parameter `n` (size of the vector) is either 1024 or 32k.
* Group unswitched: proof in `G1`
* Group switched: proof in `G2`

## Parameter Generation
See `veccom-paramgen`

## Commit


|Function|  n = 1024, groups unswitched | n = 1024, groups switched | n = 32768, groups unswitched | n = 32768, groups switched | main cost |
|---|---:|---:|---:|---:|:---|
| new commitment without pre-computation |  55.5 ms | 169.38 ms | 1.145 s |  | sum of n product |
| new commitment with pre-computation = 3 | 54.7 ms | 168.45 ms  |1.145 s |  | sum of n product |
| new commitment with pre-computation = 256 | 43.1 ms | 127.35 ms | 1.525 s |  |sum of n product |
| commitment update without pre-computation | 0.335 ms |1.03 ms ||  | 2 hash_to_field + g1_mul |
| commitment update with pre-computation = 3 | 0.158 ms|0.51 ms ||  |2 hash_to_field + g1_mul |
| commitment update with pre-computation = 256 | 0.072 ms |0.20 ms ||  | 2 hash_to_field + g1_mul |

## Proof

|Function| n = 1024, groups unswitched | n = 1024, groups switched | n = 32768, groups unswitched | n = 32768, groups switched | main cost |
|---|---:|---:|---:|---:|:---|
| new proof without pre-computation | 55.3 ms |  169.49 ms | 1.146 s| |  sum of n product |
| new proof with pre-computation = 3 | 55.1 ms|  169.93 ms |1.149 s| | sum of n product |
| new proof with pre-computation = 256 | 45.9 ms |  132.14 ms |1.524 s| |  sum of n product |
| proof update without pre-computation | 0.355 ms| 1.09 ms || | hash_to_field + g1_mul |
| proof update with pre-computation = 3 | 0.160 ms | 0.49 ms || | hash_to_field + g1_mul |
| proof update with pre-computation = 256 | 0.075 ms | 0.21 ms || | hash_to_field + g1_mul |

## Verify

|Function|  n = 1024, groups unswitched | n = 1024, groups switched |  n = 32768, groups unswitched | n = 32768, groups switched | main cost |
|---|---:|---:|---:|---:|---:|
|Verify| 4.78 ms |7.43 ms|| | hash_to_field + 2 g1_mul + pairing_product |





<!---
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



## Commitments in G1, optimize for Aggregation

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


## Commitments in G2, optimize for verification

### Cross commit, AWS Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz (Slower than MBP),


## Aggregation and batch verification

Aggregate, n = 1024,

|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|---:|
| 2 | 2.3516 ms | 6.6624 ms | 9.2198 ms | 12.504 ms | 18.710 ms |
| 4 | 3.5158 ms | 12.362 ms | 17.215 ms | 24.122 ms | 36.409 ms |
| 8 | 5.4517 ms | 23.394 ms | 32.687 ms | 46.656 ms | 70.670 ms |
| 16 | 8.8560 ms | 44.613 ms | 62.978 ms | 90.965 ms | 139.36 ms |
| 32 | 14.419 ms | 85.447 ms | 122.75 ms | 178.81 ms | 275.19 ms |
| 64 | 23.750 ms | 166.54 ms | 239.94 ms | 352.68 ms | 545.42 ms |
| 128 | 40.804 ms | 325.86 ms | 473.62 ms | 698.58 ms | 1.0861 s |
| 256 | 71.169 ms | 643.56 ms | 936.40 ms | 1.3865 s | 2.1624 s |
| 1024 | 226.19 ms | 2.5090 s | 3.6813 s | 5.4959 s | 8.6015 s |

Verify, n = 1024,

|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|---:|
| 2 | 6.2661 ms | 7.0151 ms | 7.5966 ms | 8.7508 ms | 10.651 ms |
| 4 | 8.3564 ms | 9.7969 ms | 11.229 ms | 13.286 ms | 16.996 ms |
| 8 | 12.640 ms | 15.353 ms | 18.059 ms | 22.434 ms | 30.055 ms |
| 16 | 21.168 ms | 26.512 ms | 32.036 ms | 40.606 ms | 55.966 ms |
| 32 | 38.107 ms | 49.050 ms | 59.832 ms | 77.247 ms | 107.45 ms |
| 64 | 72.167 ms | 93.481 ms | 115.44 ms | 150.00 ms | 211.20 ms |
| 128 | 140.30 ms | 183.03 ms | 227.01 ms | 296.67 ms | 418.67 ms |
| 256 | 278.45 ms | 363.90 ms | 451.67 ms | 589.26 ms | 833.27 ms |
| 1024 | 1.1255 s | 1.4682 s | 1.8176 s | 2.3741 s | 3.3469 s |

Aggregate, n = 16,

|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|---:|
| 2 | 2.2754 ms | 6.4782 ms | 9.0132 ms | 12.102 ms | 18.043 ms |
| 4 | 3.4240 ms | 11.987 ms | 16.399 ms | 22.862 ms | 34.824 ms |
| 8 | 5.3665 ms | 22.724 ms | 31.374 ms | 44.314 ms | 68.379 ms |
| 16 | 8.5402 ms | 42.790 ms | 60.802 ms | 87.166 ms | 134.64 ms |
| 32 | 13.662 ms | 81.808 ms | 117.25 ms | 171.88 ms | 264.20 ms |
| 64 | 22.766 ms | 162.26 ms | 229.76 ms | 338.09 ms | 526.07 ms |
| 128 | 39.129 ms | 313.29 ms | 454.76 ms | 671.85 ms | 1.0438 s |
| 256 | 67.745 ms | 621.47 ms | 901.82 ms | 1.3351 s | 2.0813 s |
| 1024 | 225.20 ms | 2.5125 s | 3.6854 s | 5.4858 s | 8.2926 s |

Verify, n = 16,

|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|---:|
| 2 | 6.0039 ms | 6.5925 ms | 7.4894 ms | 8.4499 ms | 10.259 ms |
| 4 | 8.1267 ms | 9.2930 ms | 10.708 ms | 12.590 ms | 16.372 ms |
| 8 | 12.206 ms | 14.915 ms | 17.861 ms | 21.431 ms | 28.855 ms |
| 16 | 20.608 ms | 25.458 ms | 31.355 ms | 38.949 ms | 53.569 ms |
| 32 | 37.431 ms | 46.296 ms | 58.414 ms | 73.212 ms | 102.95 ms |
| 64 | 70.365 ms | 90.358 ms | 110.67 ms | 144.29 ms | 203.80 ms |
| 128 | 134.86 ms | 175.44 ms | 217.12 ms | 287.97 ms | 400.66 ms |
| 256 | 267.60 ms | 347.07 ms | 432.33 ms | 565.24 ms | 796.58 ms |
| 1024 | 1.1143 s | 1.4566 s | 1.8042 s | 2.3274 s | 3.1981 s |

Aggregate, n = 64,

|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|---:|
| 2 | 2.2528 ms | 6.5642 ms | 8.6771 ms | 12.402 ms | 18.157 ms |
| 4 | 3.3735 ms | 12.121 ms | 16.574 ms | 22.853 ms | 34.901 ms |
| 8 | 5.3183 ms | 22.395 ms | 30.849 ms | 44.294 ms | 68.581 ms |
| 16 | 8.3123 ms | 42.807 ms | 60.053 ms | 87.061 ms | 136.44 ms |
| 32 | 13.848 ms | 82.784 ms | 117.97 ms | 170.21 ms | 267.66 ms |
| 64 | 22.838 ms | 159.27 ms | 228.92 ms | 338.75 ms | 524.19 ms |
| 128 | 39.366 ms | 314.92 ms | 455.88 ms | 668.87 ms | 1.0425 s |
| 256 | 67.711 ms | 618.16 ms | 898.23 ms | 1.3296 s | 2.0760 s |
| 1024 | 215.89 ms | 2.4163 s | 3.5408 s | 5.2752 s | 8.2705 s |


Verify, n = 64,

|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|---:|
| 2 | 5.9693 ms | 6.5691 ms | 7.3698 ms | 8.3815 ms | 10.219 ms |
| 4 | 8.0678 ms | 9.3997 ms | 10.502 ms | 12.806 ms | 16.348 ms |
| 8 | 12.301 ms | 14.520 ms | 17.317 ms | 21.794 ms | 28.920 ms |
| 16 | 20.329 ms | 25.471 ms | 30.450 ms | 38.975 ms | 53.495 ms |
| 32 | 36.729 ms | 46.645 ms | 58.272 ms | 76.012 ms | 103.34 ms |
| 64 | 70.151 ms | 90.967 ms | 111.58 ms | 143.58 ms | 202.29 ms |
| 128 | 134.88 ms | 176.63 ms | 218.80 ms | 285.42 ms | 401.86 ms |
| 256 | 268.23 ms | 350.19 ms | 434.90 ms | 565.42 ms | 801.12 ms |
| 1024 | 1.0716 s | 1.4009 s | 1.7662 s | 2.2646 s | 3.2075 s |


Aggregate, n = 256,

|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|---:|
| 2 | 2.2356 ms | 6.8124 ms | 9.2305 ms | 12.872 ms | 19.174 ms |
| 4 | 3.6251 ms | 12.600 ms | 17.384 ms | 24.397 ms | 37.000 ms |
| 8 | 5.6017 ms | 23.435 ms | 33.161 ms | 47.220 ms | 71.258 ms |
| 16 | 8.8335 ms | 44.480 ms | 63.310 ms | 91.168 ms | 140.68 ms |
| 32 | 14.373 ms | 86.515 ms | 123.65 ms | 179.66 ms | 278.77 ms |
| 64 | 24.105 ms | 168.27 ms | 241.66 ms | 356.34 ms | 551.35 ms |
| 128 | 40.821 ms | 328.90 ms | 475.04 ms | 703.99 ms | 1.0963 s |
| 256 | 72.029 ms | 649.98 ms | 944.50 ms | 1.3965 s | 2.1831 s |
| 1024 | 215.77 ms | 2.4451 s | 3.7092 s | 5.5321 s | 8.6676 s |

Verify, n = 256,

|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |
|---|---:|---:|---:|---:|---:|
| 2 | 6.2872 ms | 7.0224 ms | 7.6953 ms | 8.7488 ms | 10.794 ms |
| 4 | 8.4477 ms | 9.7681 ms | 11.215 ms | 13.467 ms | 17.259 ms |
| 8 | 12.701 ms | 15.663 ms | 18.242 ms | 22.788 ms | 30.175 ms |
| 16 | 21.248 ms | 26.554 ms | 32.277 ms | 41.257 ms | 56.107 ms |
| 32 | 38.590 ms | 49.539 ms | 59.926 ms | 77.611 ms | 108.05 ms |
| 64 | 72.844 ms | 94.984 ms | 116.42 ms | 150.73 ms | 212.84 ms |
| 128 | 141.45 ms | 184.01 ms | 229.37 ms | 298.52 ms | 420.11 ms |
| 256 | 278.91 ms | 366.12 ms | 452.43 ms | 593.43 ms | 843.39 ms |
| 1024 | 1.0675 s | 1.4647 s | 1.8166 s | 2.3743 s | 3.3557 s |
--->
