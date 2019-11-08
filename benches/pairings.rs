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

//criterion_group!(benches, bench_ti);
//criterion_group!(benches, bench_ti, bench_aggregation);
criterion_group!(benches, bench_ti, bench_pairings, bench_aggregation);
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

fn bench_pairings(c: &mut Criterion) {
    let bench = Benchmark::new("commit_no_precomp", |b| {
        // Does not include a to_bytes conversion for the commitment, because you normally
        // would store this yourself rather than send it on the network
        let n = 32;
        let prover_params =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0)
                .unwrap()
                .0;
        bench_commit_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("commit_precomp_256", |b| {
        // Does not include a to_bytes conversion for the commitment, because you normally
        // would store this yourself rather than send it on the network
        let n = 32;
        let mut prover_params =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0)
                .unwrap()
                .0;
        prover_params.precomp_256();

        bench_commit_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("prove_no_precomp", |b| {
        // includes to_bytes conversion for the proof, because this is supposed to measure what it takes
        // to produce a proof you will send on the network
        let n = 32usize;

        let prover_params =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0)
                .unwrap()
                .0;

        bench_prove_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("prove_precomp_256", |b| {
        // includes to_bytes conversion for the proof, because this is supposed to measure what it takes
        // to produce a proof you will send on the network
        let n = 32usize;

        let mut prover_params =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0)
                .unwrap()
                .0;
        prover_params.precomp_256();

        bench_prove_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("verify", |b| {
        // includes from_bytes conversion for the proof, because you would normally get the proof from the network
        let n = 32usize;

        let (prover_params, verifier_params) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0).unwrap();

        let mut init_values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {}", i);
            init_values.push(s.into_bytes());
        }

        let mut values: Vec<&[u8]> = Vec::with_capacity(n);
        for e in init_values.iter().take(n) {
            values.push(&e);
        }

        let com = Commitment::new(&prover_params, &values).unwrap();
        let mut proofs: Vec<Vec<u8>> = vec![];
        for i in 0..n {
            let mut buf: Vec<u8> = vec![];
            let p = Proof::new(&prover_params, &values, i).unwrap();
            assert!(p.serialize(&mut buf, true).is_ok());
            proofs.push(buf);
        }

        let mut i: usize = 0;
        b.iter(|| {
            let p = Proof::deserialize::<&[u8]>(&mut proofs[i][..].as_ref(), true).unwrap();
            assert!(p.verify(&verifier_params, &com, &values[i], i));
            i = (i + 1) % n;
        });
    });

    let bench = bench.with_function("commit_update_no_precomp", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 32usize;
        let prover_params =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0)
                .unwrap()
                .0;
        bench_commit_update_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("commit_update_precomp_3", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 32usize;

        let mut prover_params =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0)
                .unwrap()
                .0;
        prover_params.precomp_3();
        bench_commit_update_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("commit_update_precomp_256", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 32usize;

        let mut prover_params =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0)
                .unwrap()
                .0;
        prover_params.precomp_256();
        bench_commit_update_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("proof_update_no_precomp", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 32usize;

        let prover_params =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0)
                .unwrap()
                .0;
        bench_proof_update_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("proof_update_precomp_3", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 32usize;

        let mut prover_params =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0)
                .unwrap()
                .0;
        prover_params.precomp_3();
        bench_proof_update_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("proof_update_precomp_256", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 32usize;

        let mut prover_params =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0)
                .unwrap()
                .0;
        prover_params.precomp_256();
        bench_proof_update_helper(&prover_params, n, b);
    });

    let bench = bench.warm_up_time(Duration::from_millis(1000));
    let bench = bench.measurement_time(Duration::from_millis(5000));
    let bench = bench.sample_size(10);

    c.bench("pairings", bench);
}

fn bench_aggregation(c: &mut Criterion) {
    // pre-compute the parameters

    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0).unwrap();
    // let mut prover_comp_3 = prover_params.clone();
    // let mut prover_comp_256 = prover_params.clone();
    let prover_params_clone = prover_params.clone();
    //    let verifier_params_clone = verifier_params.clone();
    // prover_comp_3.precomp_3();
    // prover_comp_256.precomp_256();
    let sys_param = veccom::pairings::ciphersuite::get_system_paramter(0).unwrap();

    // includes from_bytes conversion for the proof, because you would normally get the proof from the network
    let n = sys_param.n;

    let bench = Benchmark::new("aggree_128", move |b| {
        let k = 128;
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

        let com = Commitment::new(&prover_params_clone, &values).unwrap();
        let mut proofs: Vec<Proof> = vec![];
        let mut index: Vec<usize> = vec![];
        let mut value_sub_vector: Vec<&[u8]> = vec![];
        for i in 0..k {
            let p = Proof::new(&prover_params_clone, &values, i).unwrap();
            proofs.push(p);
            index.push(i);
            value_sub_vector.push(values[i]);
        }

        let mut i: usize = 0;
        b.iter(|| {
            let _agg_proof = Proof::aggregate(&com, &proofs, &index, &value_sub_vector).unwrap();
            // assert!(agg_proof.batch_verify(
            //     &verifier_params_clone,
            //     &com,
            //     &index,
            //     &value_sub_vector
            // ));
            i = (i + 1) % n;
        });
    });

    let prover_params_clone = prover_params.clone();
    //    let verifier_params_clone = verifier_params.clone();
    let bench = bench.with_function("aggree_256", move |b| {
        let k = 256;
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

        let com = Commitment::new(&prover_params_clone, &values).unwrap();
        let mut proofs: Vec<Proof> = vec![];
        let mut index: Vec<usize> = vec![];
        let mut value_sub_vector: Vec<&[u8]> = vec![];
        for i in 0..k {
            let p = Proof::new(&prover_params_clone, &values, i).unwrap();
            proofs.push(p);
            index.push(i);
            value_sub_vector.push(values[i]);
        }

        let mut i: usize = 0;
        b.iter(|| {
            let _agg_proof = Proof::aggregate(&com, &proofs, &index, &value_sub_vector).unwrap();
            // assert!(agg_proof.batch_verify(
            //     &verifier_params_clone,
            //     &com,
            //     &index,
            //     &value_sub_vector
            // ));
            i = (i + 1) % n;
        });
    });

    let prover_params_clone = prover_params.clone();
    //    let verifier_params_clone = verifier_params.clone();
    let bench = bench.with_function("aggree_all", move |b| {
        let k = n;
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

        let com = Commitment::new(&prover_params_clone, &values).unwrap();
        let mut proofs: Vec<Proof> = vec![];
        let mut index: Vec<usize> = vec![];
        let mut value_sub_vector: Vec<&[u8]> = vec![];
        for i in 0..k {
            let p = Proof::new(&prover_params_clone, &values, i).unwrap();
            proofs.push(p);
            index.push(i);
            value_sub_vector.push(values[i]);
        }

        let mut i: usize = 0;
        b.iter(|| {
            let _agg_proof = Proof::aggregate(&com, &proofs, &index, &value_sub_vector).unwrap();
            // assert!(agg_proof.batch_verify(
            //     &verifier_params_clone,
            //     &com,
            //     &index,
            //     &value_sub_vector
            // ));
            i = (i + 1) % n;
        });
    });

    let prover_params_clone = prover_params.clone();
    let verifier_params_clone = verifier_params.clone();
    let bench = bench.with_function("batch_verify_128", move |b| {
        let k = 128;
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

        let com = Commitment::new(&prover_params_clone, &values).unwrap();
        let mut proofs: Vec<Proof> = vec![];
        let mut index: Vec<usize> = vec![];
        let mut value_sub_vector: Vec<&[u8]> = vec![];
        for i in 0..k {
            let p = Proof::new(&prover_params_clone, &values, i).unwrap();
            proofs.push(p);
            index.push(i);
            value_sub_vector.push(values[i]);
        }
        let agg_proof = Proof::aggregate(&com, &proofs, &index, &value_sub_vector).unwrap();

        let mut i: usize = 0;
        b.iter(|| {
            assert!(agg_proof.batch_verify(
                &verifier_params_clone,
                &com,
                &index,
                &value_sub_vector
            ));
            i = (i + 1) % n;
        });
    });

    let prover_params_clone = prover_params.clone();
    let verifier_params_clone = verifier_params.clone();
    let bench = bench.with_function("batch_verify_256", move |b| {
        let k = 256;
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

        let com = Commitment::new(&prover_params_clone, &values).unwrap();
        let mut proofs: Vec<Proof> = vec![];
        let mut index: Vec<usize> = vec![];
        let mut value_sub_vector: Vec<&[u8]> = vec![];
        for i in 0..k {
            let p = Proof::new(&prover_params_clone, &values, i).unwrap();
            proofs.push(p);
            index.push(i);
            value_sub_vector.push(values[i]);
        }
        let agg_proof = Proof::aggregate(&com, &proofs, &index, &value_sub_vector).unwrap();

        let mut i: usize = 0;
        b.iter(|| {
            assert!(agg_proof.batch_verify(
                &verifier_params_clone,
                &com,
                &index,
                &value_sub_vector
            ));
            i = (i + 1) % n;
        });
    });

    let prover_params_clone = prover_params.clone();
    let verifier_params_clone = verifier_params.clone();
    let bench = bench.with_function("batch_verify_all", move |b| {
        let k = n;
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

        let com = Commitment::new(&prover_params_clone, &values).unwrap();
        let mut proofs: Vec<Proof> = vec![];
        let mut index: Vec<usize> = vec![];
        let mut value_sub_vector: Vec<&[u8]> = vec![];
        for i in 0..k {
            let p = Proof::new(&prover_params_clone, &values, i).unwrap();
            proofs.push(p);
            index.push(i);
            value_sub_vector.push(values[i]);
        }
        let agg_proof = Proof::aggregate(&com, &proofs, &index, &value_sub_vector).unwrap();

        let mut i: usize = 0;
        b.iter(|| {
            assert!(agg_proof.batch_verify(
                &verifier_params_clone,
                &com,
                &index,
                &value_sub_vector
            ));
            i = (i + 1) % n;
        });
    });
    let bench = bench.warm_up_time(Duration::from_millis(1000));
    let bench = bench.measurement_time(Duration::from_millis(5000));
    let bench = bench.sample_size(10);

    c.bench("pairings", bench);
}

fn bench_ti(c: &mut Criterion) {
    let bench = Benchmark::new("bench_ti_128", move |b| {
        let commit = Commitment {
            ciphersuite: 0,
            commit: pairing::bls12_381::G1::one(),
        };
        let n = 128;
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
            let _t = veccom::pairings::prove::expose_get_ti_for_testing(&commit, &index, &values);
        });
    });

    let bench = bench.with_function("bench_ti_256", move |b| {
        let commit = Commitment {
            ciphersuite: 0,
            commit: pairing::bls12_381::G1::one(),
        };
        let n = 256;
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
            let _t = veccom::pairings::prove::expose_get_ti_for_testing(&commit, &index, &values);
        });
    });

    let bench = bench.warm_up_time(Duration::from_millis(1000));
    let bench = bench.measurement_time(Duration::from_millis(5000));
    let bench = bench.sample_size(10);

    c.bench("pairings", bench);
}
