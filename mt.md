# proof generation for multithreading
* proofs in G1
* AWS with Intel(R) Xeon(R) Platinum 8124M CPU @ 3.00GHz, [spec](https://en.wikichip.org/wiki/intel/xeon_platinum/8124m)
* 3.5 GHz (1 active core) and 3.4 GHz (2-9 active cores),
* 18 threads

# proof generation with `n = 1,000,000`

| #threads | time |
|---:|---:|
| 1 | 21.7 s|
| 2 | 14.1 s|
| 3 | 11.5 s|
| 4 | 10.1 s|
| 8 | 7.93 s|
|12 | 8.05 s|
|16 | 8.04 s|


# proof generation with `n = 10,000`

| #threads | time |
|---:|---:|
| 1 | 296.2 ms|
| 2 | 189.7 ms|
| 3 | 151.3 ms|
| 4 | 130.0 ms|
| 8 | 122.3 ms|
|12 | 114.8 ms|
|16 | 109.1 ms|
