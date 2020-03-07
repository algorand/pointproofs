#[macro_use]
extern crate criterion;
extern crate ff;
extern crate pairing_plus as pairing;
extern crate rand;
extern crate veccom;

use criterion::Benchmark;
use criterion::Criterion;
use pairing::serdes::SerDes;
use rand::Rng;
use std::time::Duration;
use veccom::pairings::*;

criterion_group!(paper, one_m);
criterion_main!(paper);

fn random_index(n: usize, hamming: usize) -> Vec<usize> {
    let mut rng = rand::thread_rng();
    let mut indices = vec![0u8; n];
    let mut ctr = 0;
    while ctr < hamming {
        let try = (rng.gen::<u16>() as usize) % n;
        if indices[try] == 0 {
            ctr += 1;
            indices[try] = 1;
        }
    }
    let mut res: Vec<usize> = vec![];
    for (i, e) in indices.iter().enumerate().take(n) {
        if *e == 1 {
            res.push(i);
        }
    }
    res
}

fn one_m(c: &mut Criterion) {
    let n = 100_000;

    let mut values: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(format!("this is message number {}", i));
    }

    let mut index: Vec<usize> = Vec::with_capacity(n);
    for i in 0..n {
        index.push(i);
    }
    // generate parameter for dimension n
    let (pp, _vp) = param::paramgen_from_seed(
        "This is a very very long seed for vector commitment benchmarking",
        0,
        n,
    )
    .unwrap();
    println!("parameters generated");

    // Single proof generation
    let pp_clone = pp.clone();
    let values_clone = values.clone();
    let bench_str = format!("single_commit_n_{}_proof_new", n);
    let mut bench = Benchmark::new(bench_str, move |b| {
        b.iter(|| Proof::new(&pp_clone, &values_clone, 0).unwrap());
    });

    let thd_array = [4, 3, 2, 1];
    for num_thd in thd_array.iter() {
        let pp_clone = pp.clone();
        let values_clone = values.clone();
        let bench_str = format!("single_commit_n_{}_proof_new_thread_{}", n, *num_thd);
        let t = *num_thd;
        bench = bench.with_function(bench_str, move |b| {
            b.iter(|| Proof::new_mt(&pp_clone, &values_clone, 0, t).unwrap());
        });
    }

    let bench = bench.warm_up_time(Duration::from_millis(1000));
    let bench = bench.measurement_time(Duration::from_millis(5000));
    let bench = bench.sample_size(10);
    c.bench("paper", bench);
}
