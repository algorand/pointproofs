#[macro_use]
extern crate criterion;
extern crate pairing_plus as pairing;
extern crate veccom;

use criterion::Benchmark;
use criterion::Criterion;
use pairing::serdes::SerDes;
use std::time::Duration;
use veccom::pairings::*;

// use criterion::Bencher;
// use criterion::Benchmark;
// use criterion::Criterion;
// use pairing::serdes::SerDes;
// // use pairing::CurveProjective;
// use std::time::Duration;
// use veccom::pairings::*;

// const N_ARRAY: [usize; 6] = [256, 1024, 4096, 16384, 65536, 262144];
// const N_ARRAY: [usize; 3] = [256, 1024, 4096];
const N_ARRAY: [usize; 2] = [256, 1024];
const C_ARRAY: [usize; 3] = [1, 2, 4];
const P_ARRAY: [usize; 4] = [4, 16, 64, 256];
const MAX_P: usize = 256;

criterion_group!(
    benches,
    bench_veccom_same_commit_aggregate,
    bench_veccom_same_commit_aggregate_batch_norm,
    bench_main,
);
criterion_main!(benches);

fn bench_veccom_same_commit_aggregate(c: &mut Criterion) {
    for n in N_ARRAY.iter() {
        // generate parameter for dimension n
        let (pp, _vp) = param::paramgen_from_seed(
            "This is a very very long seed for vector commitment benchmarking",
            0,
            *n,
        )
        .unwrap();
        println!("parameters generated");

        let pp_clone = pp.clone();
        let bench_str = format!("aggregate_{}_{}", n, MAX_P);
        let bench = Benchmark::new(bench_str, move |b| {
            // values
            let mut init_values = Vec::with_capacity(*n);
            for i in 0..*n {
                let s = format!("this is message: commit {}, index {}", 0, i);
                init_values.push(s.into_bytes());
            }

            let mut values: Vec<&[u8]> = Vec::with_capacity(*n);
            for e in init_values.iter().take(*n) {
                values.push(&e);
            }

            let com = Commitment::new(&pp_clone, &values).unwrap();

            let mut proofs: Vec<Proof> = vec![];
            let mut index: Vec<usize> = vec![];
            let mut value_sub_vector: Vec<&[u8]> = vec![];
            for i in 0..MAX_P {
                proofs.push(Proof::new(&pp_clone, &values, i).unwrap());
                index.push(i);
                value_sub_vector.push(values[i]);
            }

            //            let mut i: usize = 0;
            b.iter(|| {
                let _agg_proof =
                    Proof::same_commit_aggregate(&com, &proofs, &index, &value_sub_vector, *n)
                        .unwrap();
            });
        });

        let bench = bench.warm_up_time(Duration::from_millis(1000));
        let bench = bench.measurement_time(Duration::from_millis(5000));
        let bench = bench.sample_size(10);

        c.bench("non_batch_norm", bench);
    }
}

fn bench_veccom_same_commit_aggregate_batch_norm(c: &mut Criterion) {
    for n in N_ARRAY.iter() {
        // generate parameter for dimension n
        let (pp, _vp) = param::paramgen_from_seed(
            "This is a very very long seed for vector commitment benchmarking",
            0,
            *n,
        )
        .unwrap();
        println!("parameters generated");

        let pp_clone = pp.clone();
        let bench_str = format!("aggregate_{}_{}", n, MAX_P);
        let bench = Benchmark::new(bench_str, move |b| {
            // values
            let mut init_values = Vec::with_capacity(*n);
            for i in 0..*n {
                let s = format!("this is message: commit {}, index {}", 0, i);
                init_values.push(s.into_bytes());
            }

            let mut values: Vec<&[u8]> = Vec::with_capacity(*n);
            for e in init_values.iter().take(*n) {
                values.push(&e);
            }

            let com = Commitment::new(&pp_clone, &values).unwrap();

            let mut proofs: Vec<Proof> = vec![];
            let mut index: Vec<usize> = vec![];
            let mut value_sub_vector: Vec<&[u8]> = vec![];
            for i in 0..MAX_P {
                proofs.push(Proof::new(&pp_clone, &values, i).unwrap());
                index.push(i);
                value_sub_vector.push(values[i]);
            }

            //            let mut i: usize = 0;
            b.iter(|| {
                let _agg_proof = Proof::same_commit_aggregate_batch_norm(
                    &com,
                    &proofs,
                    &index,
                    &value_sub_vector,
                    *n,
                )
                .unwrap();
            });
        });

        let bench = bench.warm_up_time(Duration::from_millis(1000));
        let bench = bench.measurement_time(Duration::from_millis(5000));
        let bench = bench.sample_size(10);

        c.bench("batch_norm", bench);
    }
}

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
    // println!("values: {:?}", value);
    // println!("commits: {:?}", commits);

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

fn bench_x_com_helper_batch_norm(c: &mut Criterion, n: usize, num_commit: usize, num_proof: usize) {
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
    // println!("values: {:?}", value);
    // println!("commits: {:?}", commits);

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
            Proof::same_commit_aggregate_batch_norm(
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
            let agg_proof = match Proof::cross_commit_aggregate_partial_batch_norm(
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
            let agg_proof = match Proof::cross_commit_aggregate_full_batch_norm(
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
                bench_x_com_helper_batch_norm(&mut c, *n, *num_commit, *num_proof);
            }
        }
    }
}
