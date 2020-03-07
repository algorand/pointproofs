#[macro_use]
extern crate criterion;
extern crate ff;
extern crate pairing_plus as pairing;
extern crate rand_core;

use criterion::Bencher;
use criterion::Benchmark;
use criterion::Criterion;
use ff::{Field, PrimeField};
use pairing::bls12_381::*;
use pairing::{CurveAffine, CurveProjective};
use rand_core::SeedableRng;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

criterion_group!(bench_mul, bench_g1_mt, bench_g1, bench_g2);
criterion_main!(bench_mul);

fn bench_sum_product_helper<G: CurveProjective>(
    basis: &Vec<G>,
    scalar: &Vec<Fr>,
    n: usize,
    b: &mut Bencher,
) {
    let mut basis_affine: Vec<G::Affine> = vec![];
    let mut scalar_repr: Vec<FrRepr> = vec![];

    for i in 0..n {
        basis_affine.push(basis[i].into_affine());
        scalar_repr.push(scalar[i].into_repr());
    }

    let scalar_u64: Vec<&[u64; 4]> = scalar_repr.iter().map(|s| &s.0).collect();

    b.iter(|| {
        CurveAffine::sum_of_products(&basis_affine, &scalar_u64);
    })
}

fn bench_sum_product_with_precomp_helper<G: CurveProjective>(
    basis: &Vec<G>,
    scalar: &Vec<Fr>,
    pp: &Vec<G::Affine>,
    n: usize,
    b: &mut Bencher,
) {
    let mut basis_affine: Vec<G::Affine> = vec![];
    let mut scalar_repr: Vec<FrRepr> = vec![];
    for i in 0..n {
        basis_affine.push(basis[i].into_affine());
        scalar_repr.push(scalar[i].into_repr());
    }

    let scalar_u64: Vec<&[u64; 4]> = scalar_repr.iter().map(|s| &s.0).collect();

    b.iter(|| {
        CurveAffine::sum_of_products_precomp_256(&basis_affine, &scalar_u64, &pp[..]);
    })
}

fn bench_g1_mt(c: &mut Criterion) {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let sample_array = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];
    let thread_array = [1, 2, 4, 8];

    for e in sample_array.iter() {
        let sample = *e;
        let mut basis: Vec<G1Affine> = vec![];
        let mut scalar: Vec<FrRepr> = vec![];

        for _ in 0..sample {
            let tmp = G1::random(&mut rng);
            basis.push(tmp.into_affine());
            scalar.push(Fr::random(&mut rng).into_repr());
        }

        for f in thread_array.iter() {
            let thread_size = *f;
            let batch = sample / thread_size;
            let bench_str = format!("with {} threads", thread_size);

            let mut thread = Vec::with_capacity(thread_size);

            for i in 0..thread_size {
                thread.push((
                    basis[batch * i..batch * (i + 1)].to_vec(),
                    scalar[batch * i..batch * (i + 1)].to_vec(),
                ));
            }

            let bench = Benchmark::new(&bench_str, move |b| {
                b.iter(|| {
                    let mut handles = vec![];
                    let shared_buf = Arc::new(Mutex::new(vec![]));
                    let tc = thread.clone();
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
        }
    }
}

fn bench_g2(c: &mut Criterion) {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let sample_array = [2, 4, 8, 16, 32, 64, 128, 1024, 2048, 4096, 8192];

    for e in sample_array.iter() {
        let sample = *e;

        let mut basis: Vec<G2> = vec![];
        let mut scalar: Vec<Fr> = vec![];
        let mut pp: Vec<G2Affine> = vec![G2Affine::zero(); sample * 256];

        for i in 0..sample {
            let tmp = G2::random(&mut rng);
            tmp.into_affine()
                .precomp_256(&mut pp[i * 256..(i + 1) * 256]);
            basis.push(tmp);
            scalar.push(Fr::random(&mut rng));
        }

        let bench_str = format!("sum_of_prod");
        let basis_clone = basis.clone();
        let scalar_clone = scalar.clone();
        let bench = Benchmark::new(&bench_str, move |b| {
            bench_sum_product_helper(&basis_clone, &scalar_clone, sample, b);
        });

        let bench_str = format!("sum_of_prod, with pp");
        let basis_clone = basis.clone();
        let scalar_clone = scalar.clone();
        let pp_clone = pp.clone();
        let bench = bench.with_function(&bench_str, move |b| {
            bench_sum_product_with_precomp_helper(
                &basis_clone,
                &scalar_clone,
                &pp_clone,
                sample,
                b,
            );
        });

        let bench_str = format!("serial_mul");
        let bench = bench.with_function(&bench_str, move |b| {
            b.iter(|| {
                let mut res = G2::zero();
                for i in 0..sample {
                    let mut tmp = basis[i];
                    tmp.mul_assign(scalar[i]);
                    res.add_assign(&tmp);
                }
            })
        });

        let bench = bench.warm_up_time(Duration::from_millis(1000));
        let bench = bench.measurement_time(Duration::from_millis(5000));
        let bench = bench.sample_size(10);
        let bench_str = format!("G2:{}_elements", sample);
        c.bench(&bench_str, bench);
    }
}

fn bench_g1(c: &mut Criterion) {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let sample_array = [2, 4, 8, 16, 32, 64, 128, 1024, 2048, 4096, 8192];

    for e in sample_array.iter() {
        let sample = *e;

        let mut basis: Vec<G1> = vec![];
        let mut scalar: Vec<Fr> = vec![];
        let mut pp: Vec<G1Affine> = vec![G1Affine::zero(); sample * 256];

        for i in 0..sample {
            let tmp = G1::random(&mut rng);
            tmp.into_affine()
                .precomp_256(&mut pp[i * 256..(i + 1) * 256]);
            basis.push(tmp);
            scalar.push(Fr::random(&mut rng));
        }

        let bench_str = format!("sum_of_prod");
        let basis_clone = basis.clone();
        let scalar_clone = scalar.clone();
        let bench = Benchmark::new(&bench_str, move |b| {
            bench_sum_product_helper(&basis_clone, &scalar_clone, sample, b);
        });

        let bench_str = format!("sum_of_prod, with pp");
        let basis_clone = basis.clone();
        let scalar_clone = scalar.clone();
        let pp_clone = pp.clone();
        let bench = bench.with_function(&bench_str, move |b| {
            bench_sum_product_with_precomp_helper(
                &basis_clone,
                &scalar_clone,
                &pp_clone,
                sample,
                b,
            );
        });

        let bench_str = format!("serial_mul");
        let bench = bench.with_function(&bench_str, move |b| {
            b.iter(|| {
                let mut res = G1::zero();
                for i in 0..sample {
                    let mut tmp = basis[i];
                    tmp.mul_assign(scalar[i]);
                    res.add_assign(&tmp);
                }
            })
        });

        let bench = bench.warm_up_time(Duration::from_millis(1000));
        let bench = bench.measurement_time(Duration::from_millis(5000));
        let bench = bench.sample_size(10);
        let bench_str = format!("G1_{}_elements", sample);
        c.bench(&bench_str, bench);
    }
}
