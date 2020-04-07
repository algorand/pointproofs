#[macro_use]
extern crate criterion;
extern crate ff;
extern crate pairing_plus as pairing;
extern crate rand_core;

use criterion::Benchmark;
use criterion::Criterion;
use ff::{Field, PrimeField};
use pairing::bls12_381::*;
use pairing::{CurveAffine, CurveProjective};
use rand_core::SeedableRng;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

criterion_group!(bench_mt, bench_g1_mt);
criterion_main!(bench_mt);

fn bench_g1_mt(c: &mut Criterion) {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let sample_array = [100, 10_000, 1_000_000];
    let thread_array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    for e in sample_array.iter() {
        let sample = *e;
        let mut basis: Vec<G1Affine> = vec![];
        let mut scalar: Vec<FrRepr> = vec![];

        for _ in 0..sample {
            let tmp = G1::random(&mut rng);
            basis.push(tmp.into_affine());
            scalar.push(Fr::random(&mut rng).into_repr());
        }
        let scalar_clone = scalar.clone();
        let basis_clone = basis.clone();
        let bench_str = format!("1 shot");
        let bench = Benchmark::new(&bench_str, move |b| {
            b.iter(|| {
                let fr_u64: Vec<&[u64; 4]> = scalar_clone.iter().map(|x| &x.0).collect();
                let _res = G1Affine::sum_of_products(&basis_clone[..], &fr_u64);
            })
        });
        let bench = bench.warm_up_time(Duration::from_millis(1000));
        let bench = bench.measurement_time(Duration::from_millis(5000));
        let bench = bench.sample_size(100);
        let bench_str = format!("G1, sum of {} products", sample);

        c.bench(&bench_str, bench);

        for f in thread_array.iter() {
            let thread_size = *f;
            let batch = sample / thread_size;
            let bench_str = format!("with {} threads, mt", thread_size);

            let mut thread = Vec::with_capacity(thread_size);
            for i in 0..thread_size {
                thread.push((
                    basis[batch * i..batch * (i + 1)].to_vec(),
                    scalar[batch * i..batch * (i + 1)].to_vec(),
                ));
            }
            let thread_clone = thread.clone();
            let bench = Benchmark::new(&bench_str, move |b| {
                b.iter(|| {
                    let mut handles = vec![];
                    let shared_buf = Arc::new(Mutex::new(vec![]));
                    let tc = thread_clone.clone();
                    for (basis_local, scalar_local) in tc {
                        let buf_local = Arc::clone(&shared_buf);
                        let handle = thread::spawn(move || {
                            let fr_u64: Vec<&[u64; 4]> =
                                scalar_local.iter().map(|x| &x.0).collect();
                            let tmp = G1Affine::sum_of_products(&basis_local[..], &fr_u64);
                            let mut v = buf_local.lock().unwrap();
                            v.push(tmp);
                        });
                        handles.push(handle);
                    }

                    for handle in handles {
                        handle.join().unwrap();
                    }
                    let buf_unwrap = &*shared_buf.lock().unwrap();
                    let mut res2 = G1::zero();
                    for e in buf_unwrap {
                        res2.add_assign(&e);
                    }
                })
            });

            let bench = bench.warm_up_time(Duration::from_millis(1000));
            let bench = bench.measurement_time(Duration::from_millis(5000));
            let bench = bench.sample_size(100);
            let bench_str = format!("G1, sum of {} products", sample);

            c.bench(&bench_str, bench);

            let bench_str = format!("with {} threads, st", thread_size);
            let thread_clone = thread.clone();
            let bench = Benchmark::new(&bench_str, move |b| {
                b.iter(|| {
                    let tc = thread_clone.clone();
                    let mut res2 = G1::zero();
                    for (basis_local, scalar_local) in tc {
                        let fr_u64: Vec<&[u64; 4]> = scalar_local.iter().map(|x| &x.0).collect();
                        let tmp = G1Affine::sum_of_products(&basis_local[..], &fr_u64);
                        res2.add_assign(&tmp);
                    }
                })
            });
            let bench = bench.warm_up_time(Duration::from_millis(1000));
            let bench = bench.measurement_time(Duration::from_millis(5000));
            let bench = bench.sample_size(100);
            let bench_str = format!("G1, sum of {} products", sample);
            c.bench(&bench_str, bench);
        }
    }
}
