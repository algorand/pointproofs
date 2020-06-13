// this file is part of the pointproofs.
// it provides extra benchmarks using parameters with pre-compution

#[macro_use]
extern crate criterion;
extern crate pairing_plus as pairing;
extern crate pointproofs;

use criterion::Bencher;
use criterion::Benchmark;
use criterion::Criterion;
use pairing::serdes::SerDes;
use pointproofs::pairings::param::*;
use pointproofs::pairings::*;
use std::time::Duration;

criterion_group!(benches, bench_pre);
criterion_main!(benches);

fn bench_commit_helper(prover_params: &ProverParams, n: usize, b: &mut Bencher) {
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_values.iter().take(n) {
        values.push(&e);
    }

    b.iter(|| Commitment::new(prover_params, &values));
}

fn bench_prove_helper(prover_params: &ProverParams, n: usize, b: &mut Bencher) {
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_values.iter().take(n) {
        values.push(&e);
    }

    let mut i: usize = 0;
    b.iter(|| {
        let mut buf: Vec<u8> = vec![];
        Proof::new(prover_params, &values, i)
            .unwrap()
            .serialize(&mut buf, true)
            .unwrap();
        i = (i + 1) % n;
        buf
    });
}

fn bench_commit_des_and_update_helper(prover_params: &ProverParams, n: usize, b: &mut Bencher) {
    let mut init_old_values = Vec::with_capacity(n);
    let mut init_new_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is old message number {}", i);
        init_old_values.push(s.into_bytes());
        let t = format!("this is new message number {}", i);
        init_new_values.push(t.into_bytes());
    }

    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);
    let mut new_values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        old_values.push(&init_old_values[i]);
        new_values.push(&init_new_values[i]);
    }
    let mut buf: Vec<u8> = vec![];
    let com = Commitment::new(&prover_params, &old_values).unwrap();
    assert!(com.serialize(&mut buf, true).is_ok());
    let mut i: usize = 0;
    b.iter(|| {
        let mut tmp = Commitment::deserialize::<&[u8]>(&mut buf[..].as_ref(), true).unwrap();
        tmp.update(prover_params, i, &old_values[i], &new_values[i])
            .unwrap();
        i = (i + 1) % n;
    });
}

fn bench_commit_update_helper(prover_params: &ProverParams, n: usize, b: &mut Bencher) {
    let mut init_old_values = Vec::with_capacity(n);
    let mut init_new_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is old message number {}", i);
        init_old_values.push(s.into_bytes());
        let t = format!("this is new message number {}", i);
        init_new_values.push(t.into_bytes());
    }

    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);
    let mut new_values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        old_values.push(&init_old_values[i]);
        new_values.push(&init_new_values[i]);
    }

    let com = Commitment::new(&prover_params, &old_values).unwrap();
    let mut i: usize = 0;
    b.iter(|| {
        let mut tmp = com.clone();
        tmp.update(prover_params, i, &old_values[i], &new_values[i])
            .unwrap();
        i = (i + 1) % n;
    });
}

fn bench_proof_des_and_update_helper(prover_params: &ProverParams, n: usize, b: &mut Bencher) {
    // Does not include to/from bytes conversion, because this is supposed to be a local operation
    let update_index = n / 2; // We will update message number n/2 and then benchmark changing proofs for others

    let mut init_old_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is old message number {}", i);
        init_old_values.push(s.into_bytes());
    }

    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_old_values.iter().take(n) {
        old_values.push(&e);
    }

    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        let mut buf: Vec<u8> = vec![];
        let proof = Proof::new(prover_params, &old_values, i).unwrap();
        assert!(proof.serialize(&mut buf, true).is_ok());
        proofs.push(buf);
    }

    let new_value = format!("this is new message number {}", update_index).into_bytes();

    let mut i: usize = 0;
    b.iter(|| {
        let mut tmp = proofs[i].clone();
        let mut proof = Proof::deserialize::<&[u8]>(&mut tmp[..].as_ref(), true).unwrap();
        proof
            .update(
                prover_params,
                i,
                update_index,
                &old_values[update_index],
                &new_value[..].as_ref(),
            )
            .unwrap();
        i = (i + 1) % n;
        if i == update_index {
            // skip update_index
            i = (i + 1) % n;
        }
        tmp
    });
}

fn bench_proof_update_helper(prover_params: &ProverParams, n: usize, b: &mut Bencher) {
    // Does not include to/from bytes conversion, because this is supposed to be a local operation
    let update_index = n / 2; // We will update message number n/2 and then benchmark changing proofs for others

    let mut init_old_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is old message number {}", i);
        init_old_values.push(s.into_bytes());
    }

    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_old_values.iter().take(n) {
        old_values.push(&e);
    }

    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(Proof::new(prover_params, &old_values, i).unwrap());
    }

    let new_value = format!("this is new message number {}", update_index).into_bytes();

    let mut i: usize = 0;
    b.iter(|| {
        let mut tmp = proofs[i].clone();
        tmp.update(
            prover_params,
            i,
            update_index,
            &old_values[update_index],
            &new_value[..].as_ref(),
        )
        .unwrap();
        i = (i + 1) % n;
        if i == update_index {
            // skip update_index
            i = (i + 1) % n;
        }
        tmp
    });
}

fn bench_pre(c: &mut Criterion) {
    for n in &[16] {
        //    for n in &[1024, 32768] {
        // parameters
        let (prover_params, verifier_params) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, *n).unwrap();
        let mut pp3 = prover_params.clone();
        pp3.precomp_3();
        let mut pp256 = prover_params.clone();
        pp256.precomp_256();

        // commitment generation
        let prover_params_clone = prover_params.clone();
        let bench = Benchmark::new(format!("N_{}_commit_no_precomp", *n), move |b| {
            bench_commit_helper(&prover_params_clone, *n, b);
        });
        let pp3_clone = pp3.clone();
        let bench = bench.with_function(format!("N_{}_commit_precomp_3", *n), move |b| {
            bench_commit_helper(&pp3_clone, *n, b);
        });
        let pp256_clone = pp256.clone();
        let bench = bench.with_function(format!("N_{}_commit_precomp_256", *n), move |b| {
            bench_commit_helper(&pp256_clone, *n, b);
        });

        // proof generation
        let prover_params_clone = prover_params.clone();
        let bench = bench.with_function(format!("N_{}_prove_no_precomp", *n), move |b| {
            bench_prove_helper(&prover_params_clone, *n, b);
        });
        let pp3_clone = pp3.clone();
        let bench = bench.with_function(format!("N_{}_prove_precomp_3", *n), move |b| {
            bench_prove_helper(&pp3_clone, *n, b);
        });
        let pp256_clone = pp256.clone();
        let bench = bench.with_function(format!("N_{}_prove_precomp_256", *n), move |b| {
            bench_prove_helper(&pp256_clone, *n, b);
        });

        // verification
        let prover_params_clone = prover_params.clone();
        let bench = bench.with_function(format!("N_{}_verify", *n), move |b| {
            let mut init_values = Vec::with_capacity(*n);
            for i in 0..*n {
                let s = format!("this is message number {}", i);
                init_values.push(s.into_bytes());
            }

            let mut values: Vec<&[u8]> = Vec::with_capacity(*n);
            for e in init_values.iter().take(*n) {
                values.push(&e);
            }

            let com = Commitment::new(&prover_params_clone, &values).unwrap();
            let mut proofs: Vec<Vec<u8>> = vec![];
            for i in 0..*n {
                let mut buf: Vec<u8> = vec![];
                let p = Proof::new(&prover_params_clone, &values, i).unwrap();
                assert!(p.serialize(&mut buf, true).is_ok());
                proofs.push(buf);
            }

            let mut i: usize = 0;
            b.iter(|| {
                let p = Proof::deserialize::<&[u8]>(&mut proofs[i][..].as_ref(), true).unwrap();
                assert!(p.verify(&verifier_params, &com, &values[i], i));
                i = (i + 1) % *n;
            });
        });

        // commitment update
        let prover_params_clone = prover_params.clone();
        let bench = bench.with_function(format!("N_{}_commit_update_no_precomp", *n), move |b| {
            bench_commit_update_helper(&prover_params_clone, *n, b);
        });
        let prover_params_clone = prover_params.clone();
        let bench = bench.with_function(
            format!("N_{}_commit_des_and_update_no_precomp", *n),
            move |b| {
                bench_commit_des_and_update_helper(&prover_params_clone, *n, b);
            },
        );
        let pp3_clone = pp3.clone();
        let bench = bench.with_function(format!("N_{}_commit_update_precomp_3", *n), move |b| {
            bench_commit_update_helper(&pp3_clone, *n, b);
        });
        let pp3_clone = pp3.clone();
        let bench = bench.with_function(
            format!("N_{}_commit_des_and_update_precomp3", *n),
            move |b| {
                bench_commit_des_and_update_helper(&pp3_clone, *n, b);
            },
        );
        let pp256_clone = pp256.clone();
        let bench = bench.with_function(format!("N_{}_commit_update_precomp_256", *n), move |b| {
            bench_commit_update_helper(&pp256_clone, *n, b);
        });
        let pp256_clone = pp256.clone();
        let bench = bench.with_function(
            format!("N_{}_commit_des_and_update_precomp256", *n),
            move |b| {
                bench_commit_des_and_update_helper(&pp256_clone, *n, b);
            },
        );
        // proof update
        let prover_params_clone = prover_params.clone();
        let bench = bench.with_function(format!("N_{}_proof_update_no_precomp", *n), move |b| {
            bench_proof_update_helper(&prover_params_clone, *n, b);
        });
        let prover_params_clone = prover_params.clone();
        let bench = bench.with_function(
            format!("N_{}_proof_des_and_update_no_precomp", *n),
            move |b| {
                bench_proof_des_and_update_helper(&prover_params_clone, *n, b);
            },
        );
        let pp3_clone = pp3.clone();
        let bench = bench.with_function(format!("N_{}_proof_update_precomp_3", *n), move |b| {
            bench_proof_update_helper(&pp3_clone, *n, b);
        });
        let pp3_clone = pp3.clone();
        let bench = bench.with_function(
            format!("N_{}_proof_des_and_update_precomp3", *n),
            move |b| {
                bench_proof_des_and_update_helper(&pp3_clone, *n, b);
            },
        );
        let pp256_clone = pp256.clone();
        let bench = bench.with_function(format!("N_{}_proof_update_precomp_256", *n), move |b| {
            bench_proof_update_helper(&pp256_clone, *n, b);
        });
        let pp256_clone = pp256.clone();
        let bench = bench.with_function(
            format!("N_{}_proof_des_and_update_precomp256", *n),
            move |b| {
                bench_proof_des_and_update_helper(&pp256_clone, *n, b);
            },
        );

        let bench = bench.warm_up_time(Duration::from_millis(1000));
        let bench = bench.measurement_time(Duration::from_millis(5000));
        let bench = bench.sample_size(10);

        c.bench("pairings", bench);
    }
}
