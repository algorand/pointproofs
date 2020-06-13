# benchmark results on pointproofs

## Setup

* AWS Intel(R) Xeon(R) CPU E5-2686 v4 @ __2.30__ GHz (Slower than MBP).
* Public parameter `n` (size of the vector) is either 1024 or 32k.


## Parameter Generation
See `pointproofs-paramgen`

## Basics


|Function|  n = 1024, proof in G1 | n = 1024, proof in G2 | n = 32768, proof in G1 | n = 32768, proof in G2 | main cost |
|---|---:|---:|---:|---:|:---|
| new commitment |  55.5 ms | 169.38 ms | 1.145 s | 3.30 s | sum of n product |
| commitment update | 0.335 ms |1.03 ms |  0.675 ms  | 1.02 ms  | 2 hash_to_field + g1_mul |
| new proof | 55.3 ms |  169.49 ms | 1.146 s| 3.3 s |  sum of n product |
| proof update | 0.355 ms| 1.09 ms | ??? | ??? | hash_to_field + g1_mul |
| verify | 4.78 ms |7.43 ms|__8.64 ms__| 7.25 ms| hash_to_field + 2 g1_mul + pairing_product |



## Aggregation

* aggregate cross: input a list of same-commit aggregated proofs, output a cross-commit aggregated proof.
* aggregate within + cross: input a list of non-aggregated proofs, output a cross-commit aggregated proof.
* batch verify: input a cross-commit aggregated proof, verify the proof.

### N = 1024, proof in G2


|Operation | # Commitments | 1 proofs per commit |  8 proofs per commit |  16 proofs per commit |  32 proofs per commit |
|:---|---:|---:|---:|---:|---:|
| aggregate cross| 64 | 61 ms | 65 ms | 66 ms | 67 ms |
| aggregate within + cross | 64 | 68 ms | 1.02 s | 1.07 s | 2.07 s |  
| batch verify | 64 | 212 ms | 152.3 ms | 211.6 ms | 494 ms |
|  |  |  |  |  |  |  |
| aggregate cross | 256 | 178 ms | 194 ms | 195 ms | 198 ms |
| aggregate within + cross | 256 | 135 ms | 3.19 s | 5.00 s | 7.40 s |
| batch verify | 256 | 825 ms | 1.52 s | 1.68 s | 2.62 s |
|  |  |  |  |  |  |  |
| aggregate cross | 1024 | 223 ms | 254 ms | 0.565 ms | 618 ms |
| aggregate within + cross | 1024 | 571 ms | 12.2 s | 19.2 s | 30.42 s |
| batch verify | 1024 | 2.24 s | 5.12 s | 7.35 s | 11.13 s|

### N = 1024, proof in G1


|Operation | # Commitments | 1 proofs per commit |  8 proofs per commit |  16 proofs per commit |  32 proofs per commit |
|:---|---:|---:|---:|---:|---:|
| aggregate cross | 64 | 7.45 ms | 8.6 ms | 8.5 ms | 8.75 ms |
| aggregate within + cross| 64 | 9.06 ms | 117.7 s | 298.8 s | 291.5 s |  
| batch verify | 64 | 124.9 ms | 376.5 ms | 580.3 ms | 865.3 ms |
|  |  |  |  |  |  |  |
| aggregate cross | 256 | 22.1 ms | 26.5 ms | 26.9 ms | 27.9 ms |
| aggregate within + cross| 256 | 28.7 ms | 453.0 ms | 715.6 ms | 1.15 s |
| batch verify | 256 | 486.8 ms | 1.47 s | 2.23 s | 3.45 s |
|  |  |  |  |  |  |  |
| aggregate cross | 1024 | 71.3 ms | 88.6 ms | 90.5 ms | 94.4 ms |
| aggregate within + cross| 1024 | 97.7 ms | 1.80 s | 2.85 s | 4.59 s |
| batch verify | 1024 | 1.95 s | 5.88 s | 8.88 s | 13.78 s|

### N = 32768, proof in G2


|Operation | # Commitments | 1 proofs per commit |  8 proofs per commit |  16 proofs per commit |  32 proofs per commit |
|:---|---:|---:|---:|---:|---:|
| aggregate cross | 64 | 62.7 ms | 65.5 ms | 66.4 ms |  67.0 ms |
| aggregate within + cross| 64 | 69.3  ms | 835.3 ms |  1.03 s |  1.81 s |  
| batch verify | 64 |  211.5 ms | 571.2 ms |  617.1 ms | 909 ms |  
|  |  |  |  |  |  |  |
| aggregate cross | 256 |  61.3 ms |  193 ms |  194 ms | 197  ms |
| aggregate within + cross| 256 | 70.5 ms | 3.22 s |  4.95 s | 7.65 s |
| batch verify | 256 |  819 ms |  1.50 s | 1.65 s | 2.90 s |
|  |  |  |  |  |  |  |
| aggregate cross | 1024 | 67.7 ms |  421.1 ms | 322.7 ms | 572.8 ms |
| aggregate within + cross| 1024 | 225.6 ms | 12.1  s | 18.9 s |  30.3 s |
| batch verify | 1024 | 2.6 s |  5.02 s | 7.56 s | 10.9 s|


### N = 32768, proof in G1


|Operation | # Commitments | 1 proofs per commit |  8 proofs per commit |  16 proofs per commit |  32 proofs per commit |
|:---|---:|---:|---:|---:|---:|
| aggregate cross | 64 | 7.34 ms | 8.43 ms | 8.57 ms |  8.77 ms |
| aggregate within + cross| 64 | 9.00  ms | 115.0 ms |  180.7 ms |  280.1 ms |  
| batch verify | 64 |  123.2 ms | 368.4 ms |  556.6 ms | 862.9 ms |  
|  |  |  |  |  |  |  |
| aggregate cross | 256 |  22.2 ms |  8.56 ms | 27.3  ms | 81.3 ms |
| aggregate within + cross| 256 | 28.8 ms | 906.0 ms |  1.42 s | 2.38 s |
| batch verify | 256 |  486.7 ms |  3.40 s | 4.12 s | 7.82 s |
|  |  |  |  |  |  |  |
| aggregate cross | 1024 | 208.3 ms | 125 ms | 91.0 ms | 94.9 ms |
| aggregate within + cross| 1024 |  286.0 ms | 3.98 s | 6.32 s |  10.1 s |
| batch verify | 1024 | 4.46 s | 12.9 s |  19.6 s | 30.8 s|

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
# benchmark results on `sum_of_prod` functions

* `sum of prod` is always faster than `serial` method
* `sum of prod with precomp256` is better than `sum of prod` if the number of basis is smaller than, say, 1024.

## Setup

* MBP (To be tested over AWS where the noise is less)

## G1 result
|#basis| serial | sum_of_prod | sum_of_prod w pre_comp256|
|---|:---|:---|:---|
|2|0.484|0.442| 0.055|
|4|0.990|0.674| 0.098|
|8|2.000|0.995| 0.189|
|16|3.713|1.514|0.355|
|32|7.771|2.446|0.732|
|64|15.17|4.100|1.474|
|128|29.90|6.260|2.786|
|1024|244.5|32.00|29.82|
|2048|489.6|56.34|60.63|
|4096|983.7|101.1|117.0|
|8192|1956.|173.5|223.5|

## G2 result
|#basis| serial | sum_of_prod | sum_of_prod w pre_comp256|
|---|:---|:---|:---|
|2|1.684|1.603|0.187|
|4|3.166|2.210|0.340|
|8|6.998|3.389|0.680|
|16|13.28|5.476|1.288|
|32|26.61|8.609|2.592|
|64|52.07|13.65|5.135|
|128|104.7|22.58|10.97|
|1024|824.4|108.9|87.28|
|2048|1658.|193.8|171.2|
|4096|3230.|348.1|340.0|
|8192|6668.|631.3|680.4|
