#[macro_use]
extern crate criterion;
extern crate ff;
extern crate pairing_plus as pairing;
extern crate veccom;

use criterion::Bencher;
use criterion::Benchmark;
use criterion::Criterion;
use pairing::serdes::SerDes;
// use pairing::CurveProjective;
use ff::PrimeField;
use pairing::bls12_381::*;
use pairing::CurveProjective;
use std::time::Duration;
use veccom::pairings::*;

// const N_ARRAY: [usize; 6] = [256, 1024, 4096, 16384, 65536, 262144];
// const N_ARRAY: [usize; 3] = [256, 1024, 4096];
const N_ARRAY: [usize; 4] = [16, 64, 256, 1024];
const P_ARRAY: [usize; 4] = [2, 4, 8, 16];
const C_ARRAY: [usize; 9] = [2, 4, 8, 16, 32, 64, 128, 256, 1024];
//const PWD: &str = "/home/ubuntu/pre-com/";

criterion_group!(
    benches,
    bench_main,
    // bench_veccom_cross_commit_aggregate,
    // bench_veccom_cross_commit_batch_verify,
    // bench_veccom_with_param,
    // bench_aggregation_with_param,
    // bench_ti
);

criterion_main!(benches);

fn bench_x_com_helper(c: &mut Criterion, n: usize, num_commit: usize, num_proof: usize) {
    // generate parameter for dimension n
    let (pp, vp) = paramgen::paramgen_from_seed(
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
        value_sub_vector.push(value_sub_vector_per_commit);
        index.push(index_per_commit)
    }
    println!("Subset formed");
    let bench_str = format!(
        "x-com aggregate: n = {}, c = {}, p = {}",
        n, num_commit, num_proof
    );
    let commits_clone = commits.clone();
    let index_clone = index.clone();
    let value_sub_vector_clone = value_sub_vector.clone();
    c.bench_function(&bench_str, move |b| {
        let file_name = format!(
            "benches/x-com-aggregate-n{}-c{}-p{}.proof",
            n, num_commit, num_proof
        );
        let mut file = std::fs::File::create(file_name).unwrap();
        b.iter(|| {
            let agg_proof = match Proof::cross_commit_aggregate(
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
    c.bench_function(&bench_str, move |b| {
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
//
// fn bench_veccom_cross_commit_aggregate(c: &mut Criterion) {
//     for n in N_ARRAY.iter() {
//         let file_name = format!("benches/pre-gen-param/{}.param", n);
//         let mut file = std::fs::File::open(file_name).unwrap();
//         let (pp, vp) = paramgen::read_param(&mut file).unwrap();
//         let pp_clone = pp.clone();
//
//         for p in P_ARRAY.iter() {
//             for c in C_ARRAY.iter() {
//                 let bench_str =
//                     format!("crossaggregate: n = {}, commits = {}, proofs = {}", n, c, p);
//                 let bench = Benchmark::new(bench_str, move |b| {
//                     let n = pp_clone.n;
//
//                     //        let mut values: Vec<Vec<Vec<u8>>> = vec![];
//                     let mut commits: Vec<Commitment> = vec![];
//                     let mut proofs: Vec<Vec<Proof>> = vec![];
//                     let mut index: Vec<Vec<usize>> = vec![];
//                     let mut value_sub_vector: Vec<Vec<Vec<u8>>> = vec![];
//
//                     for j in 0..*c {
//                         let mut init_values = Vec::with_capacity(n);
//                         for i in 0..n {
//                             let s = format!("this is message: commit {}, index {}", j, i);
//                             init_values.push(s.into_bytes());
//                         }
//
//                         let file_name =
//                             format!("benches/pre-gen-com-and-proof/tmp/n_{}_com_{}.commit", n, j);
//                         let mut file = match std::fs::File::open(&file_name) {
//                             Err(e) => panic!("file {} not exist {}", &file_name, e),
//                             Ok(p) => p,
//                         };
//                         let tmp_com = Commitment::deserialize(&mut file, true).unwrap();
//                         let mut tmp_proofs: Vec<Proof> = vec![];
//                         let mut tmp_index: Vec<usize> = vec![];
//                         let mut tmp_value_sub_vector: Vec<Vec<u8>> = vec![];
//                         for i in 0..*p {
//                             //proofs.push(Proof::new(prover_params, &old_values, i).unwrap());
//                             let file_name = format!(
//                                 "benches/pre-gen-com-and-proof/tmp/n_{}_com_{}_proof_{}.proof",
//                                 n, j, i
//                             );
//                             let mut file = match std::fs::File::open(&file_name) {
//                                 Err(e) => panic!("file {} not exist {}", &file_name, e),
//                                 Ok(p) => p,
//                             };;
//                             let proof = Proof::deserialize(&mut file, true).unwrap();
//
//                             assert!(
//                                 proof.verify(&vp, &tmp_com, &init_values[i], i),
//                                 "proof verification failed for {}",
//                                 i
//                             );
//                             tmp_proofs.push(proof);
//                             tmp_index.push(i);
//                             tmp_value_sub_vector.push(init_values[i].clone());
//                         }
//
//                         //            values.push(init_values);
//                         commits.push(tmp_com);
//                         proofs.push(tmp_proofs);
//                         index.push(tmp_index);
//                         value_sub_vector.push(tmp_value_sub_vector);
//                     }
//
//                     //            let mut i: usize = 0;
//                     b.iter(|| {
//                         let agg_proof = Proof::cross_commit_aggregate(
//                             &commits,
//                             &proofs,
//                             &index,
//                             &value_sub_vector,
//                             n,
//                         )
//                         .unwrap();
//                         let file_name = format!("tmp/cross_agg_{}.proof", n);
//                         let mut file = std::fs::File::create(file_name).unwrap();
//                         agg_proof.serialize(&mut file, true).unwrap();
//                     });
//                 });
//
//                 let bench = bench.warm_up_time(Duration::from_millis(1000));
//                 let bench = bench.measurement_time(Duration::from_millis(5000));
//                 let bench = bench.sample_size(10);
//
//                 c.bench("pairings", bench);
//             }
//         }
//     }
// }
//
// fn bench_veccom_cross_commit_batch_verify(c: &mut Criterion) {
//     for n in N_ARRAY.iter() {
//         let file_name = format!("benches/pre-gen-param/{}.param", n);
//         let mut file = std::fs::File::open(file_name).unwrap();
//         let (pp, vp) = paramgen::read_param(&mut file).unwrap();
//         let pp_clone = pp.clone();
//         let bench_str = format!("cross_verify_{}_{}", n, MAX_P);
//         let bench = Benchmark::new(bench_str, move |b| {
//             let n = pp_clone.n;
//
//             // values
//             // let mut init_values = Vec::with_capacity(n);
//             // for i in 0..n {
//             //     let s = format!("this is message: commit {}, index {}", 0, i);
//             //     init_values.push(s.into_bytes());
//             // }
//             //
//             // let mut values: Vec<&[u8]> = Vec::with_capacity(n);
//             // for e in init_values.iter().take(n) {
//             //     values.push(&e);
//             // }
//
//             let mut values: Vec<Vec<Vec<u8>>> = vec![];
//             let mut commits: Vec<Commitment> = vec![];
//             let mut index: Vec<Vec<usize>> = vec![];
//             let mut value_sub_vector: Vec<Vec<Vec<u8>>> = vec![];
//
//             for j in 0..MAX_C {
//                 let mut init_values = Vec::with_capacity(n);
//                 for i in 0..n {
//                     let s = format!("this is message: commit {}, index {}", j, i);
//                     init_values.push(s.into_bytes());
//                 }
//
//                 let file_name =
//                     format!("benches/pre-gen-com-and-proof/tmp/n_{}_com_{}.commit", n, j);
//                 let mut file = match std::fs::File::open(&file_name) {
//                     Err(e) => panic!("file {} not exist {}", &file_name, e),
//                     Ok(p) => p,
//                 };
//                 let tmp_com = Commitment::deserialize(&mut file, true).unwrap();
//                 let mut tmp_index: Vec<usize> = vec![];
//                 let mut tmp_value_sub_vector: Vec<Vec<u8>> = vec![];
//                 for i in 0..MAX_P {
//                     tmp_index.push(i);
//                     tmp_value_sub_vector.push(init_values[i].clone());
//                 }
//                 values.push(init_values);
//                 commits.push(tmp_com);
//                 index.push(tmp_index);
//                 value_sub_vector.push(tmp_value_sub_vector);
//             }
//
//             let file_name = format!("tmp/cross_agg_{}.proof", n);
//             let mut file = std::fs::File::open(file_name).unwrap();
//             let agg_proof = Proof::deserialize(&mut file, true).unwrap();
//             //        println!("{:?} \n{:?}\n", index, values);
//             //            let mut i: usize = 0;
//             b.iter(|| {
//                 assert!(agg_proof.cross_commit_batch_verify(
//                     &vp,
//                     &commits,
//                     &index,
//                     &value_sub_vector
//                 ));
//             });
//         });
//
//         let bench = bench.warm_up_time(Duration::from_millis(1000));
//         let bench = bench.measurement_time(Duration::from_millis(5000));
//         let bench = bench.sample_size(10);
//
//         c.bench("pairings", bench);
//     }
// }
