#[macro_use]
extern crate criterion;
extern crate ff;
extern crate pairing_plus as pairing;
extern crate veccom;

use criterion::Benchmark;
use criterion::Criterion;
use pairing::serdes::SerDes;
use std::time::Duration;
use veccom::pairings::*;

criterion_group!(paper, aggregate, single_commit,);
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
    for i in 0..8 {
        let tmp = Proof::new(&pp, &values, i).unwrap();
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
    let bench = bench.sample_size(100);
    c.bench("paper", bench);
}

fn aggregate(c: &mut Criterion) {
    let dim = 1000;
    let num_com_array = [10, 1000, 2000, 3000, 4000, 5000];

    // generate parameter for dimension n
    let (pp, vp) = param::paramgen_from_seed(
        "This is a very very long seed for vector commitment benchmarking",
        0,
        dim,
    )
    .unwrap();
    println!("parameters generated");
    for s in num_com_array.iter() {
        let num_com = *s;
        let mut values: Vec<Vec<String>> = vec![];
        let mut single_proof_commit_index: Vec<Vec<usize>> = vec![];
        let mut single_proof_commit_value: Vec<Vec<String>> = vec![];
        let mut eight_proof_commit_index: Vec<Vec<usize>> = vec![];
        let mut eight_proof_commit_value: Vec<Vec<String>> = vec![];
        for i in 0..num_com {
            let mut tmp_value: Vec<String> = vec![];
            for j in 0..dim {
                tmp_value.push(format!("this is message #{} for commit #{}", j, i));
            }
            values.push(tmp_value);
            let mut tmp_value_sub_vector: Vec<String> = vec![];
            for j in 0..8 {
                tmp_value_sub_vector.push(format!("this is message #{} for commit #{}", j, i));
            }
            single_proof_commit_index.push(vec![0]);
            single_proof_commit_value.push(vec![tmp_value_sub_vector[0].clone()]);
            eight_proof_commit_index.push(vec![0, 1, 2, 3, 4, 5, 6, 7]);
            eight_proof_commit_value.push(tmp_value_sub_vector.clone());
        }

        let mut com_list: Vec<Commitment> = vec![];
        let mut single_proof_list: Vec<Proof> = vec![];
        let mut agg_proof_list: Vec<Proof> = vec![];

        for i in 0..num_com {
            // commit
            let tmp_com = Commitment::new(&pp, &values[i]).unwrap();

            // proofs
            let mut tmp_proof_list: Vec<Proof> = vec![];
            for j in 0..8 {
                let tmp_proof = Proof::new(&pp, &values[i], j).unwrap();
                tmp_proof_list.push(tmp_proof);
            }
            // store the first proof for each commit
            single_proof_list.push(tmp_proof_list[0].clone());

            // aggregate proofs
            let agg_proof = Proof::same_commit_aggregate(
                &tmp_com,
                &tmp_proof_list,
                &eight_proof_commit_index[i],
                &eight_proof_commit_value[i],
                dim,
            )
            .unwrap();
            agg_proof_list.push(agg_proof);

            com_list.push(tmp_com);
        }

        println!("Pre-generation finished");

        // single proof, proof aggregate
        let com_list_clone = com_list.clone();
        let single_proof_list_clone = single_proof_list.clone();
        let single_proof_commit_index_clone = single_proof_commit_index.clone();
        let single_proof_commit_value_clone = single_proof_commit_value.clone();
        let bench_str = format!(
            "aggregation_n={}_commit={}_single_proof_per_commitment",
            dim, num_com
        );
        let bench = Benchmark::new(bench_str, move |b| {
            b.iter(|| {
                Proof::cross_commit_aggregate_partial(
                    &com_list_clone,
                    &single_proof_list_clone,
                    &single_proof_commit_index_clone,
                    &single_proof_commit_value_clone,
                    dim,
                )
                .unwrap();
            });
        });

        // 8 proofs, proof aggregate
        let com_list_clone = com_list.clone();
        let eight_proof_list_clone = agg_proof_list.clone();
        let eight_proof_commit_index_clone = eight_proof_commit_index.clone();
        let eight_proof_commit_value_clone = eight_proof_commit_value.clone();
        let bench_str = format!(
            "aggregation_n={}_commit={}_8_proof_per_commitment",
            dim, num_com
        );
        let bench = bench.with_function(bench_str, move |b| {
            b.iter(|| {
                Proof::cross_commit_aggregate_partial(
                    &com_list_clone,
                    &eight_proof_list_clone,
                    &eight_proof_commit_index_clone,
                    &eight_proof_commit_value_clone,
                    dim,
                )
                .unwrap();
            });
        });

        // single proof, batch verification
        let vp_clone = vp.clone();
        let com_list_clone = com_list.clone();
        let single_proof_list_clone = single_proof_list.clone();
        let single_proof_commit_index_clone = single_proof_commit_index.clone();
        let single_proof_commit_value_clone = single_proof_commit_value.clone();
        let agg_proof = Proof::cross_commit_aggregate_partial(
            &com_list_clone,
            &single_proof_list_clone,
            &single_proof_commit_index_clone,
            &single_proof_commit_value_clone,
            dim,
        )
        .unwrap();

        let mut agg_proof_bytes: Vec<u8> = vec![];
        agg_proof.serialize(&mut agg_proof_bytes, true).unwrap();

        let bench_str = format!(
            "batch_verify_n={}_commit={}_single_proof_per_commitment",
            dim, num_com
        );
        let bench = bench.with_function(bench_str, move |b| {
            b.iter(|| {
                let p = Proof::deserialize::<&[u8]>(&mut agg_proof_bytes.as_ref(), true).unwrap();
                assert!(p.cross_commit_batch_verify(
                    &vp_clone,
                    &com_list_clone,
                    &single_proof_commit_index_clone,
                    &single_proof_commit_value_clone,
                ))
            });
        });

        // 8 proofs, batch verification
        let vp_clone = vp.clone();
        let com_list_clone = com_list.clone();
        let eight_proof_list_clone = agg_proof_list.clone();
        let eight_proof_commit_index_clone = eight_proof_commit_index.clone();
        let eight_proof_commit_value_clone = eight_proof_commit_value.clone();
        let agg_proof = Proof::cross_commit_aggregate_partial(
            &com_list_clone,
            &eight_proof_list_clone,
            &eight_proof_commit_index_clone,
            &eight_proof_commit_value_clone,
            dim,
        )
        .unwrap();
        let mut agg_proof_bytes: Vec<u8> = vec![];
        agg_proof.serialize(&mut agg_proof_bytes, true).unwrap();

        let bench_str = format!(
            "batch_verify_n={}_commit={}_8_proof_per_commitment",
            dim, num_com
        );
        let bench = bench.with_function(bench_str, move |b| {
            b.iter(|| {
                let p = Proof::deserialize::<&[u8]>(&mut agg_proof_bytes.as_ref(), true).unwrap();
                assert!(p.cross_commit_batch_verify(
                    &vp_clone,
                    &com_list_clone,
                    &eight_proof_commit_index_clone,
                    &eight_proof_commit_value_clone,
                ))
            });
        });

        let bench = bench.warm_up_time(Duration::from_millis(1000));
        let bench = bench.measurement_time(Duration::from_millis(5000));
        let bench = bench.sample_size(10);
        c.bench("paper", bench);
    }
}
