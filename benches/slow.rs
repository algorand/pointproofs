#[macro_use]
extern crate criterion;
extern crate pairing_plus as pairing;
extern crate veccom;

use criterion::Bencher;
use criterion::Benchmark;
use criterion::Criterion;
use pairing::serdes::SerDes;
use pairing::CurveProjective;
use std::time::Duration;
use veccom::pairings::*;

//const N_ARRAY: [usize; 6] = [256, 1024, 4096, 16384, 65536, 262144];
const N_ARRAY: [usize; 3] = [256, 1024, 4096];

criterion_group!(
    benches,
    bench_veccom_with_param,
    bench_aggregation_with_param,
    bench_ti
);

criterion_main!(benches);

fn bench_commit_helper(prover_params: &ProverParams, b: &mut Bencher) {
    let n = prover_params.n;
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

fn bench_prove_helper(prover_params: &ProverParams, b: &mut Bencher) {
    let n = prover_params.n;
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

fn bench_commit_update_helper(prover_params: &ProverParams, b: &mut Bencher) {
    let n = prover_params.n;
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

fn bench_proof_update_helper(prover_params: &ProverParams, b: &mut Bencher) {
    let n = prover_params.n;

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

fn bench_veccom_with_param(c: &mut Criterion) {
    for n in N_ARRAY.iter() {
        let file_name = format!("benches/pre-gen-param/{}.param", n);
        let mut file = std::fs::File::open(file_name).unwrap();
        let (pp, vp) = paramgen::read_param(&mut file).unwrap();

        let file_name = format!("benches/pre-gen-param/{}_pre3.param", n);
        let mut file = std::fs::File::open(file_name).unwrap();
        let pp3 = ProverParams::deserialize(&mut file, true).unwrap();

        let file_name = format!("benches/pre-gen-param/{}_pre256.param", n);
        let mut file = std::fs::File::open(file_name).unwrap();
        let pp256 = ProverParams::deserialize(&mut file, true).unwrap();

        let pp_clone = pp.clone();
        let bench_str = format!("commit_no_precomp_{}", n);
        let bench = Benchmark::new(bench_str, move |b| {
            // Does not include a to_bytes conversion for the commitment, because you normally
            // would store this yourself rather than send it on the network
            bench_commit_helper(&pp_clone, b);
        });

        let pp3_clone = pp3.clone();
        let bench_str = format!("commit_precomp3_{}", n);
        let bench = bench.with_function(bench_str, move |b| {
            // Does not include a to_bytes conversion for the commitment, because you normally
            // would store this yourself rather than send it on the network

            bench_commit_helper(&pp3_clone, b);
        });

        let pp256_clone = pp256.clone();
        let bench_str = format!("commit_precomp256_{}", n);
        let bench = bench.with_function(bench_str, move |b| {
            // Does not include a to_bytes conversion for the commitment, because you normally
            // would store this yourself rather than send it on the network
            bench_commit_helper(&pp256_clone, b);
        });

        let pp_clone = pp.clone();
        let bench_str = format!("prove_no_precomp_{}", n);
        let bench = bench.with_function(bench_str, move |b| {
            // includes to_bytes conversion for the proof, because this is supposed to measure what it takes
            // to produce a proof you will send on the network
            bench_prove_helper(&pp_clone, b);
        });
        let pp3_clone = pp3.clone();
        let bench_str = format!("prove_precomp3_{}", n);
        let bench = bench.with_function(bench_str, move |b| {
            // includes to_bytes conversion for the proof, because this is supposed to measure what it takes
            // to produce a proof you will send on the network

            bench_prove_helper(&pp3_clone, b);
        });

        let pp256_clone = pp256.clone();
        let bench_str = format!("prove_precomp256_{}", n);
        let bench = bench.with_function(bench_str, move |b| {
            // includes to_bytes conversion for the proof, because this is supposed to measure what it takes
            // to produce a proof you will send on the network

            bench_prove_helper(&pp256_clone, b);
        });

        let pp_clone = pp.clone();
        let vp_clone = vp.clone();
        let bench_str = format!("verify_{}", n);

        let bench = bench.with_function(bench_str, move |b| {
            let n = pp_clone.n;

            let mut init_values = Vec::with_capacity(n);
            for i in 0..n {
                let s = format!("this is message number {}", i);
                init_values.push(s.into_bytes());
            }
            let mut values: Vec<&[u8]> = Vec::with_capacity(n);
            for e in init_values.iter().take(n) {
                values.push(&e);
            }
            let com = Commitment::new(&pp_clone, &values).unwrap();
            let mut proofs: Vec<Vec<u8>> = vec![];
            for i in 0..n {
                let mut buf: Vec<u8> = vec![];
                let p = Proof::new(&pp_clone, &values, i).unwrap();
                assert!(p.serialize(&mut buf, true).is_ok());
                proofs.push(buf);
            }
            let mut i: usize = 0;
            b.iter(|| {
                let p = Proof::deserialize::<&[u8]>(&mut proofs[i][..].as_ref(), true).unwrap();
                assert!(p.verify(&vp_clone, &com, &values[i], i));
                i = (i + 1) % n;
            });
        });

        let pp_clone = pp.clone();
        let bench_str = format!("commit_update_no_precomp_{}", n);
        let bench = bench.with_function(bench_str, move |b| {
            // Does not include to/from bytes conversion, because this is supposed to be a local operation

            bench_commit_update_helper(&pp_clone, b);
        });

        let pp3_clone = pp3.clone();
        let bench_str = format!("commit_update_precomp3_{}", n);

        let bench = bench.with_function(bench_str, move |b| {
            // Does not include to/from bytes conversion, because this is supposed to be a local operation

            bench_commit_update_helper(&pp3_clone, b);
        });

        let pp256_clone = pp256.clone();
        let bench_str = format!("commit_update_precomp256_{}", n);

        let bench = bench.with_function(bench_str, move |b| {
            // Does not include to/from bytes conversion, because this is supposed to be a local operation

            bench_commit_update_helper(&pp256_clone, b);
        });

        let pp_clone = pp.clone();
        let bench_str = format!("proof_update_no_precomp_{}", n);
        let bench = bench.with_function(bench_str, move |b| {
            // Does not include to/from bytes conversion, because this is supposed to be a local operation

            bench_proof_update_helper(&pp_clone, b);
        });

        let pp3_clone = pp3.clone();
        let bench_str = format!("proof_update_precomp3_{}", n);
        let bench = bench.with_function(bench_str, move |b| {
            // Does not include to/from bytes conversion, because this is supposed to be a local operation

            bench_proof_update_helper(&pp3_clone, b);
        });

        let pp256_clone = pp256.clone();
        let bench_str = format!("proof_update_precomp256_{}", n);
        let bench = bench.with_function(bench_str, move |b| {
            // Does not include to/from bytes conversion, because this is supposed to be a local operation

            bench_proof_update_helper(&pp256_clone, b);
        });

        let bench = bench.warm_up_time(Duration::from_millis(1000));
        let bench = bench.measurement_time(Duration::from_millis(5000));
        let bench = bench.sample_size(10);

        c.bench("pairings", bench);
    }
}

fn bench_aggregation_with_param(c: &mut Criterion) {
    for n in N_ARRAY.iter() {
        let file_name = format!("benches/pre-gen-param/{}.param", n);
        let mut file = std::fs::File::open(file_name).unwrap();
        let (pp, vp) = paramgen::read_param(&mut file).unwrap();
        let pp_clone = pp.clone();
        let bench_str = format!("aggregate_{}", n);
        let bench = Benchmark::new(bench_str, move |b| {
            let n = pp_clone.n;
            // values
            let mut init_values = Vec::with_capacity(n);
            for i in 0..n {
                let s = format!("this is message number {}", i);
                init_values.push(s.into_bytes());
            }

            let mut values: Vec<&[u8]> = Vec::with_capacity(n);
            for e in init_values.iter().take(n) {
                values.push(&e);
            }

            let com = Commitment::new(&pp_clone, &values).unwrap();
            let mut proofs: Vec<Proof> = vec![];
            let mut index: Vec<usize> = vec![];
            let mut value_sub_vector: Vec<&[u8]> = vec![];
            for i in 0..n {
                let p = Proof::new(&pp_clone, &values, i).unwrap();
                proofs.push(p);
                index.push(i);
                value_sub_vector.push(values[i]);
            }

            let mut i: usize = 0;
            b.iter(|| {
                let _agg_proof =
                    Proof::aggregate(&com, &proofs, &index, &value_sub_vector, n).unwrap();
                i = (i + 1) % n;
            });
        });

        let pp_clone = pp.clone();
        let vp_clone = vp.clone();
        let bench_str = format!("batch_verify_{}", n);
        let bench = bench.with_function(bench_str, move |b| {
            let n = pp_clone.n;
            let mut init_values = Vec::with_capacity(n);
            for i in 0..n {
                let s = format!("this is message number {}", i);
                init_values.push(s.into_bytes());
            }

            let mut values: Vec<&[u8]> = Vec::with_capacity(n);
            for e in init_values.iter().take(n) {
                values.push(&e);
            }

            let com = Commitment::new(&pp_clone, &values).unwrap();
            let mut proofs: Vec<Proof> = vec![];
            let mut index: Vec<usize> = vec![];
            let mut value_sub_vector: Vec<&[u8]> = vec![];
            for i in 0..n {
                let p = Proof::new(&pp, &values, i).unwrap();
                proofs.push(p);
                index.push(i);
                value_sub_vector.push(values[i]);
            }
            let agg_proof = Proof::aggregate(&com, &proofs, &index, &value_sub_vector, n).unwrap();

            let mut i: usize = 0;
            b.iter(|| {
                assert!(agg_proof.batch_verify(&vp_clone, &com, &index, &value_sub_vector));
                i = (i + 1) % n;
            });
        });
        let bench = bench.warm_up_time(Duration::from_millis(1000));
        let bench = bench.measurement_time(Duration::from_millis(5000));
        let bench = bench.sample_size(10);

        c.bench("pairings", bench);
    }
}

fn bench_ti(c: &mut Criterion) {
    for t in N_ARRAY.iter() {
        let n = *t;
        let bench = Benchmark::new("bench_ti_new_128", move |b| {
            let commit = Commitment {
                ciphersuite: 0,
                commit: pairing::bls12_381::G1::one(),
            };
            // values
            let mut init_values = Vec::with_capacity(n);
            let mut index: Vec<usize> = vec![];
            for i in 0..n {
                let s = format!("this is message number {}", i);
                init_values.push(s.into_bytes());
                index.push(i);
            }

            let mut values: Vec<&[u8]> = Vec::with_capacity(n);
            for e in init_values.iter().take(n) {
                values.push(&e);
            }
            b.iter(|| {
                let _t =
                    veccom::pairings::hash_to_field_veccom::hash_to_ti(&commit, &index, &values, n);
            });
        });

        let bench = bench.warm_up_time(Duration::from_millis(1000));
        let bench = bench.measurement_time(Duration::from_millis(5000));
        let bench = bench.sample_size(10);
        c.bench("pairings", bench);
    }
}
