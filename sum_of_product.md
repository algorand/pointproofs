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
