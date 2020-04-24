// this file is part of the pointproofs.
// it benches the cost for cross commitments aggregation and batch verification

#[macro_use]
extern crate criterion;
extern crate ff_zeroize as ff;
extern crate pairing_plus as pairing;
extern crate pointproofs;

use criterion::Benchmark;
use criterion::Criterion;
use pairing::serdes::SerDes;
use pointproofs::pairings::*;
use std::time::Duration;

const N_ARRAY: [usize; 2] = [1024, 32768];
const P_ARRAY: [usize; 4] = [1, 8, 16, 32];
const C_ARRAY: [usize; 1] = [4096];

criterion_group!(benches, bench_main,);

criterion_main!(benches);

fn bench_x_com_helper(c: &mut Criterion, n: usize, num_commit: usize, num_proof: usize) {
    // generate parameter for dimension n
    let (pp, vp) = param::paramgen_from_seed(
        "This is a very very long seed for vector commitment benchmarking",
        0,
        n,
    )
    .unwrap();
    println!("parameters generated");
    // a list of values that one will commit to, as well as the commitments and proofs
    let mut value: Vec<Vec<String>> = vec![];
    let mut commits: Vec<Commitment> = vec![];
    let mut proofs: Vec<Vec<Proof>> = vec![];
    for commit_index in 0..num_commit {
        let mut value_per_commit: Vec<String> = vec![];
        let mut proofs_per_commit: Vec<Proof> = vec![];
        for proof_index in 0..n {
            value_per_commit.push(format!(
                "this is message: commit {}, index {}",
                commit_index, proof_index
            ));
        }
        for proof_index in 0..num_proof {
            proofs_per_commit.push(match Proof::new(&pp, &value_per_commit, proof_index) {
                Err(e) => panic!(e),
                Ok(p) => p,
            });
        }
        commits.push(match Commitment::new(&pp, &value_per_commit) {
            Err(e) => panic!(e),
            Ok(p) => p,
        });
        value.push(value_per_commit);
        proofs.push(proofs_per_commit);
    }

    println!("Pre-generating finished");
    // now we do x-com aggregation
    let mut value_sub_vector: Vec<Vec<String>> = vec![];
    let mut index: Vec<Vec<usize>> = vec![];
    let mut proofs_per_commit = vec![];

    for commit_index in 0..num_commit {
        let mut value_sub_vector_per_commit: Vec<String> = vec![];
        let mut index_per_commit: Vec<usize> = vec![];
        for proof_index in 0..num_proof {
            value_sub_vector_per_commit.push(format!(
                "this is message: commit {}, index {}",
                commit_index, proof_index
            ));
            index_per_commit.push(proof_index);
        }
        proofs_per_commit.push(
            Proof::same_commit_aggregate(
                &commits[commit_index],
                &proofs[commit_index],
                &index_per_commit,
                &value_sub_vector_per_commit,
                n,
            )
            .unwrap(),
        );
        value_sub_vector.push(value_sub_vector_per_commit);
        index.push(index_per_commit);
    }
    println!("Subset formed");

    let bench_str = format!(
        "x-com aggregate partial: n = {}, c = {}, p = {}",
        n, num_commit, num_proof
    );
    let commits_clone = commits.clone();
    let index_clone = index.clone();
    let value_sub_vector_clone = value_sub_vector.clone();

    let bench = Benchmark::new(&bench_str, move |b| {
        let file_name = format!(
            "benches/x-com-aggregate-n{}-c{}-p{}-partial.proof",
            n, num_commit, num_proof
        );
        let mut file = std::fs::File::create(file_name).unwrap();
        b.iter(|| {
            let agg_proof = match Proof::cross_commit_aggregate_partial(
                &commits_clone,
                &proofs_per_commit,
                &index_clone,
                &value_sub_vector_clone,
                n,
            ) {
                Ok(p) => p,
                Err(e) => panic!(e),
            };

            agg_proof.serialize(&mut file, true).unwrap();
        })
    });

    let bench_str = format!(
        "x-com aggregate full: n = {}, c = {}, p = {}",
        n, num_commit, num_proof
    );
    let commits_clone = commits.clone();
    let index_clone = index.clone();
    let value_sub_vector_clone = value_sub_vector.clone();

    let bench = bench.with_function(&bench_str, move |b| {
        let file_name = format!(
            "benches/x-com-aggregate-n{}-c{}-p{}.proof",
            n, num_commit, num_proof
        );
        let mut file = std::fs::File::create(file_name).unwrap();
        b.iter(|| {
            let agg_proof = match Proof::cross_commit_aggregate_full(
                &commits_clone,
                &proofs,
                &index_clone,
                &value_sub_vector_clone,
                n,
            ) {
                Ok(p) => p,
                Err(e) => panic!(e),
            };

            agg_proof.serialize(&mut file, true).unwrap();
        })
    });

    let bench_str = format!(
        "x-com batch verify: n = {}, c = {}, p = {}",
        n, num_commit, num_proof
    );
    let bench = bench.with_function(&bench_str, move |b| {
        let file_name = format!(
            "benches/x-com-aggregate-n{}-c{}-p{}.proof",
            n, num_commit, num_proof
        );
        let mut file = std::fs::File::open(file_name).unwrap();
        let agg_proof = Proof::deserialize(&mut file, true).unwrap();
        b.iter(|| {
            assert!(
                agg_proof.cross_commit_batch_verify(&vp, &commits, &index, &value_sub_vector),
                "verification failed"
            );
        })
    });

    let bench = bench.warm_up_time(Duration::from_millis(1000));
    let bench = bench.measurement_time(Duration::from_millis(5000));
    let bench = bench.sample_size(20);

    c.bench("pairings", bench);
}

fn bench_main(mut c: &mut Criterion) {
    for n in N_ARRAY.iter() {
        for num_commit in C_ARRAY.iter() {
            for num_proof in P_ARRAY.iter() {
                bench_x_com_helper(&mut c, *n, *num_commit, *num_proof);
            }
        }
    }
}
