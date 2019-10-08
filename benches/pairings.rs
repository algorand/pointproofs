#[macro_use]
extern crate criterion;
extern crate veccom;

use criterion::Bencher;
use criterion::Benchmark;
use criterion::Criterion;
use std::time::Duration;
use veccom::pairings::*;

criterion_group!(benches, bench_pairings);
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

    b.iter(|| commit(prover_params, &values));
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
        let p = convert_proof_to_bytes(&prove(prover_params, &values, i));
        i = (i + 1) % n;
        p
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

    let com = commit(&prover_params, &old_values);
    let mut i: usize = 0;
    b.iter(|| {
        commit_update(prover_params, &com, i, &old_values[i], &new_values[i]);
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
        proofs.push(prove(prover_params, &old_values, i));
    }

    let new_value = format!("this is new message number {}", update_index).into_bytes();

    let mut i: usize = 0;
    b.iter(|| {
        let new_proof = proof_update(
            prover_params,
            &proofs[i],
            i,
            update_index,
            &old_values[update_index],
            &new_value,
        );
        i = (i + 1) % n;
        if i == update_index {
            // skip update_index
            i = (i + 1) % n;
        }
        new_proof
    });
}

fn bench_pairings(c: &mut Criterion) {
    let bench = Benchmark::new("commit_no_precomp", |b| {
        // Does not include a to_bytes conversion for the commitment, because you normally
        // would store this yourself rather than send it on the network
        let n = 1000usize;

        let prover_params = paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n).0;

        bench_commit_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("commit_precomp_256", |b| {
        // Does not include a to_bytes conversion for the commitment, because you normally
        // would store this yourself rather than send it on the network
        let n = 1000usize;

        let mut prover_params = paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n).0;
        prover_params.precomp_256();

        bench_commit_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("prove_no_precomp", |b| {
        // includes to_bytes conversion for the proof, because this is supposed to measure what it takes
        // to produce a proof you will send on the network
        let n = 1000usize;

        let prover_params = paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n).0;

        bench_prove_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("prove_precomp_256", |b| {
        // includes to_bytes conversion for the proof, because this is supposed to measure what it takes
        // to produce a proof you will send on the network
        let n = 1000usize;

        let mut prover_params = paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n).0;
        prover_params.precomp_256();

        bench_prove_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("verify", |b| {
        // includes from_bytes conversion for the proof, because you would normally get the proof from the network
        let n = 100usize;

        let (prover_params, verifier_params) =
            paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n);

        let mut init_values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {}", i);
            init_values.push(s.into_bytes());
        }

        let mut values: Vec<&[u8]> = Vec::with_capacity(n);
        for e in init_values.iter().take(n) {
            values.push(&e);
        }

        let com = commit(&prover_params, &values);
        let mut proofs = Vec::with_capacity(n);
        for i in 0..n {
            proofs.push(convert_proof_to_bytes(&prove(&prover_params, &values, i)));
        }

        let mut i: usize = 0;
        b.iter(|| {
            assert!(verify(
                &verifier_params,
                &com,
                &convert_bytes_to_proof(&proofs[i]),
                &values[i],
                i
            ));
            i = (i + 1) % n;
        });
    });

    let bench = bench.with_function("commit_update_no_precomp", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 1000usize;

        let prover_params = paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n).0;
        bench_commit_update_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("commit_update_precomp_3", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 1000usize;

        let mut prover_params = paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n).0;
        prover_params.precomp_3();
        bench_commit_update_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("commit_update_precomp_256", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 1000usize;

        let mut prover_params = paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n).0;
        prover_params.precomp_256();
        bench_commit_update_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("proof_update_no_precomp", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 1000usize;

        let prover_params = paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n).0;
        bench_proof_update_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("proof_update_precomp_3", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 1000usize;

        let mut prover_params = paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n).0;
        prover_params.precomp_3();
        bench_proof_update_helper(&prover_params, n, b);
    });

    let bench = bench.with_function("proof_update_precomp_256", |b| {
        // Does not include to/from bytes conversion, because this is supposed to be a local operation
        let n = 1000usize;

        let mut prover_params = paramgen_from_seed("This is Leo's Favourite Seed".as_ref(), n).0;
        prover_params.precomp_256();
        bench_proof_update_helper(&prover_params, n, b);
    });

    let bench = bench.warm_up_time(Duration::from_millis(1000));
    let bench = bench.measurement_time(Duration::from_millis(5000));
    let bench = bench.sample_size(10);

    c.bench("pairings", bench);
}
