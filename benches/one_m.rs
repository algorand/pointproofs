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
    let n = 1000_000;

    let mut values: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(format!("this is message number {}", i));
    }

    let mut index: Vec<usize> = Vec::with_capacity(n);
    for i in 0..n {
        index.push(i);
    }
    // generate parameter for dimension n
    let (pp, vp) = param::paramgen_from_seed(
        "This is a very very long seed for vector commitment benchmarking",
        0,
        n,
    )
    .unwrap();
    // let mut pp256 = pp.clone();
    // pp256.precomp_256();
    // let mut vp256 = vp.clone();
    // vp256.precomp_256();
    println!("parameters generated");

    // let mut com = Commitment::new(&pp, &values).unwrap();
    // let mut proofs: Vec<Proof> = vec![];
    // let mut set: Vec<usize> = vec![];
    // let mut value_sub_vector: Vec<String> = vec![];
    // for i in 0..8 {
    //     let tmp = Proof::new(&pp, &values, i).unwrap();
    //     proofs.push(tmp);
    //     set.push(i);
    //     value_sub_vector.push(values[i].clone());
    // }
    // println!("pre_generation finished");

    // Commitment creation (we have for N=1024)
    // let pp_clone = pp.clone();
    // let values_clone = values.clone();
    // let bench_str = format!("single_commit_n_{}_commit_new", n);
    // let mut bench = Benchmark::new(bench_str, move |b| {
    //     b.iter(|| Commitment::new(&pp_clone, &values_clone).unwrap());
    // });

    // Single proof generation
    let pp_clone = pp.clone();
    let values_clone = values.clone();
    let bench_str = format!("single_commit_n_{}_proof_new", n);
    let bench = Benchmark::new(bench_str, move |b| {
        b.iter(|| Proof::new(&pp_clone, &values_clone, 0).unwrap());
    });

    let bench = bench.warm_up_time(Duration::from_millis(1000));
    let bench = bench.measurement_time(Duration::from_millis(5000));
    let bench = bench.sample_size(10);
    c.bench("paper", bench);
}
