// For a single commitment:
//

// Verify single proof (we have for N=1024)
// Verify 8 aggregated proofs (don't have)
// Update one value in the commitment (we have for N=1024)
// Update 8 values in the commitment (just 8 times the previous line, probably)

#[macro_use]
extern crate criterion;
extern crate ff;
extern crate pairing_plus as pairing;
extern crate veccom;

use criterion::Bencher;
use criterion::Benchmark;
use criterion::Criterion;
use pairing::serdes::SerDes;
use std::time::Duration;
use veccom::pairings::*;

criterion_group!(paper, single_commit);
criterion_main!(paper);

fn single_commit(c: &mut Criterion) {
    let n = 1024;

    let mut values: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(format!("this is message number {}", i));
    }
    let mut old_values: Vec<String> = Vec::with_capacity(8);
    for i in 0..8 {
        old_values.push(format!("this is message number {}", i));
    }

    let mut new_values: Vec<String> = Vec::with_capacity(8);
    for i in 0..8 {
        new_values.push(format!("this is new message number {}", i));
    }

    let mut index: Vec<usize> = Vec::with_capacity(8);
    for i in 0..8 {
        index.push(i);
    }
    // generate parameter for dimension n
    let (pp, vp) = param::paramgen_from_seed(
        "This is a very very long seed for vector commitment benchmarking",
        0,
        n,
    )
    .unwrap();
    println!("parameters generated");

    let com = Commitment::new(&pp, &values).unwrap();
    let mut proofs: Vec<Proof> = vec![];
    let mut set: Vec<usize> = vec![];
    let mut value_sub_vector: Vec<String> = vec![];
    println!("{}", 0);
    for i in 0..8 {
        let tmp = Proof::new(&pp, &values, i).unwrap();
        println!("{}", i);
        proofs.push(tmp);
        set.push(i);
        value_sub_vector.push(values[i].clone());
    }
    println!("pre_generation finished");

    // Commitment creation (we have for N=1024)
    let pp_clone = pp.clone();
    let values_clone = values.clone();
    let bench_str = format!("single_commit_n_{}_commit_new", n);
    let bench = Benchmark::new(bench_str, move |b| {
        b.iter(|| Commitment::new(&pp_clone, &values_clone).unwrap());
    });

    // Single proof generation
    let pp_clone = pp.clone();
    let values_clone = values.clone();
    let bench_str = format!("single_commit_n_{}_proof_new", n);
    let bench = bench.with_function(bench_str, move |b| {
        b.iter(|| Proof::new(&pp_clone, &values_clone, 0).unwrap());
    });

    // aggregate 8 proofs
    let pp_clone = pp.clone();
    let values_clone = values.clone();
    let proofs_clone = proofs.clone();
    let set_clone = set.clone();
    let com_clone = com.clone();
    let value_sub_vector_clone = value_sub_vector.clone();
    let bench_str = format!("single_commit_n_{}_proof_aggregate", n);
    let bench = bench.with_function(bench_str, move |b| {
        b.iter(|| {
            Proof::same_commit_aggregate(
                &com_clone,
                &proofs_clone,
                &set_clone,
                &value_sub_vector_clone,
                n,
            )
        });
    });
    // Verify 8 aggregated proofs
    // verification with des
    let vp_clone = vp.clone();
    let proof = proofs[0].clone();
    let com_clone = com.clone();
    let value = values[0].clone();
    let bench_str = format!("single_commit_n_{}_verify_bytes", n);
    let bench = bench.with_function(bench_str, move |b| {
        let mut proof_str: Vec<u8> = vec![];
        proof.serialize(&mut proof_str, true).unwrap();

        b.iter(|| {
            let proof_rec = Proof::deserialize::<&[u8]>(&mut proof_str[..].as_ref(), true).unwrap();
            proof_rec.verify(&vp_clone, &com_clone, &value, 0);
        });
    });

    // commit update
    let mut com_clone = com.clone();
    let ov = old_values[0].clone();
    let nv = new_values[0].clone();
    let bench_str = format!("single_commit_n_{}_commit_update", n);
    let bench = bench.with_function(bench_str, move |b| {
        b.iter(|| {
            com_clone.update(&pp_clone, 0, &ov, &nv).unwrap();
        });
    });

    // commit batch update
    let mut com_clone = com.clone();
    let pp_clone = pp.clone();
    let bench_str = format!("single_commit_n_{}_commit_batch_update", n);
    let bench = bench.with_function(bench_str, move |b| {
        b.iter(|| {
            com_clone
                .batch_update(&pp_clone, &index, &old_values, &new_values)
                .unwrap();
        });
    });

    let bench = bench.warm_up_time(Duration::from_millis(1000));
    let bench = bench.measurement_time(Duration::from_millis(5000));
    let bench = bench.sample_size(10);
    c.bench("paper", bench);
}
