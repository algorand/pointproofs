# bench `sum of product` with multithreading
* over G1
* AWS with Intel(R) Xeon(R) Platinum 8124M CPU @ 3.00GHz, [spec](https://en.wikichip.org/wiki/intel/xeon_platinum/8124m)
* 3.5 GHz (1 active core) and 3.4 GHz (2-9 active cores),
* 18 threads

# sum of `100` products
* baseline - single sum of product: `6.09` ms
* multi threads, parallel: running `#threads` in parallel
* multi threads, serial: running `#threads` one after anther, record the total time
* multi threads, per thread: running `#threads` one after anther, record the average time per thread (`#sums` decreases with `#threads` increases)

| #threads | multi threads, parallel   | multi threads, serial | multi threads, per thread|
|---:|---:|---:|---:|
| 1 | 6.13 ms | 6.08 ms | 6.08 ms |
| 2 | 3.78 ms | 7.42 ms | 3.71 ms |
| 3 | 3.31 ms | 8.35 ms | 2.78 ms |
| 4 | 2.51 ms | 9.24 ms | 2.31 ms |
| 5 | 3.31 ms | 10.1 ms | 2.02 ms |
| 6 | 2.88 ms | 10.3 ms | 1.72 ms |
| 7 | 3.03 ms | 11.0 ms | 1.57 ms |
| 8 | 3.02 ms | 11.3 ms | 1.31 ms |
| 9 | 3.31 ms | 12.0 ms | 1.33 ms |
| 10| 3.24 ms | 12.6 ms | 1.26 ms |
| 11| 3.26 ms | 13.0 ms | 1.18 ms |
| 12| 3.07 ms | 13.2 ms | 1.10 ms |
| 13| 2.97 ms | 13.2 ms | 1.01 ms |
| 14| 3.02 ms | 14.2 ms | 1.01 ms |
| 15| 2.85 ms | 13.9 ms | 0.93 ms |
| 16| 2.95 ms | 14.8 ms | 0.93 ms |




# sum of `10000` products
* baseline - single sum of product: `240.6` ms

| #threads | multi threads, parallel   | multi threads, serial | multi threads, per thread|
|---:|---:|---:|---:|
| 1 | 240.9 ms | 240.6 ms | 240.6 ms |
| 2 | 134.4 ms | 267.9 ms | 134.0 ms |
| 3 | 95.6 ms | 285.7 ms | 95.2 ms |
| 4 | 74.6 ms | 296.7 ms | 74.2 ms |
| 5 | 75.9 ms | 307.6 ms | 61.5 ms |
| 6 | 69.3 ms | 318.5 ms | 53.1 ms |
| 7 | 73.7 ms | 329.5 ms | 47.1 ms |
| 8 | 69.2 ms | 340.2 ms | 42.5 ms |
| 9 | 71.5 ms | 346.1 ms | 38.5 ms |
| 10| 68.2 ms | 352.6 ms | 35.3 ms |
| 11| 63.3 ms | 358.7 ms | 32.6 ms |
| 12| 59.3 ms | 364.7 ms | 30.4 ms |
| 13| 56.1 ms | 370.9 ms | 28.5 ms |
| 14| 53.5 ms | 377.1 ms | 26.9 ms |
| 15| 50.9 ms | 383.4 ms | 25.6 ms |
| 16| 49.4 ms | 389.5 ms | 24.3 ms |
