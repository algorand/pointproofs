#[macro_use]
extern crate bencher;
extern crate veccom;

use bencher::Bencher;
use veccom::merkle::*;

benchmark_group!(
    benches,
    bench_com_merkle,
    bench_tree_building_merkle,
    bench_prove_from_scratch_merkle,
    bench_prove_from_tree_merkle,
    bench_verify_merkle,
    bench_commit_update_merkle,
    bench_tree_update_merkle,
    bench_proof_update_no_helper_merkle,
    bench_proof_update_with_helper_merkle
);
benchmark_main!(benches);

fn bench_com_merkle(b: &mut Bencher) {
    let n = 1000usize;

    let params = paramgen(n);

    let mut init_values = Vec::with_capacity(n);
    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }
    for i in 0..n {
        values.push(&init_values[i]);
    }

    b.iter(|| commit_no_tree(&params, &values));
}

fn bench_tree_building_merkle(b: &mut Bencher) {
    let n = 1000usize;

    let params = paramgen(n);

    let mut init_values = Vec::with_capacity(n);
    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }
    for i in 0..n {
        values.push(&init_values[i]);
    }

    b.iter(|| commit_with_tree(&params, &values));
}

fn bench_prove_from_scratch_merkle(b: &mut Bencher) {
    let n = 1000usize;

    let params = paramgen(n);

    let mut init_values = Vec::with_capacity(n);
    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let mut i: usize = 0;
    b.iter(|| {
        let p = prove_from_scratch(&params, &values, i);
        i = (i + 1) % n;
        p
    });
}

fn bench_prove_from_tree_merkle(b: &mut Bencher) {
    let n = 1000usize;

    let params = paramgen(n);

    let mut init_values = Vec::with_capacity(n);
    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let tree = commit_with_tree(&params, &values);
    let mut i: usize = 0;
    b.iter(|| {
        let p = prove_from_tree(&params, &tree, i);
        i = (i + 1) % n;
        p
    });
}

fn bench_verify_merkle(b: &mut Bencher) {
    let n = 1000usize;

    let params = paramgen(n);

    let mut init_values = Vec::with_capacity(n);
    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let com = commit_no_tree(&params, &values);
    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(prove_from_scratch(&params, &values, i));
    }

    let mut i: usize = 0;
    b.iter(|| {
        assert!(verify(&params, &com, &proofs[i], values[i], i));
        i = (i + 1) % n;
    });
}

fn bench_commit_update_merkle(b: &mut Bencher) {
    let n = 1000usize;

    let params = paramgen(n);

    let mut init_values = Vec::with_capacity(n);
    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);
    let mut new_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is old message number {}", i);
        init_values.push(s.into_bytes());
        let t = format!("this is new message number {}", i);
        new_values.push(t.into_bytes());
    }

    for i in 0..n {
        old_values.push(&init_values[i]);
    }

    let mut i: usize = 0;
    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(prove_from_scratch(&params, &old_values, i));
    }

    b.iter(|| {
        commit_update(&params, i, &proofs[i], &new_values[i]);
        i = (i + 1) % n;
    });
}

fn bench_tree_update_merkle(b: &mut Bencher) {
    let n = 1000usize;

    let params = paramgen(n);

    let mut init_values = Vec::with_capacity(n);
    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);
    let mut new_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is old message number {}", i);
        init_values.push(s.into_bytes());
        let t = format!("this is new message number {}", i);
        new_values.push(t.into_bytes());
    }
    for i in 0..n {
        old_values.push(&init_values[i]);
    }

    let mut i: usize = 0;

    let mut tree = commit_with_tree(&params, &old_values);

    b.iter(|| {
        tree_update(&params, i, &new_values[i], &mut tree);
        i = (i + 1) % n;
    });
}

fn bench_proof_update_no_helper_merkle(b: &mut Bencher) {
    let n = 1000usize;
    let update_index = n / 2; // We will update message number n/2 and then benchmark changing proofs for others

    let params = paramgen(n);

    let mut init_values = Vec::with_capacity(n);
    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);

    for i in 0..n {
        let s = format!("this is old message number {}", i);
        init_values.push(s.into_bytes());
    }
    for i in 0..n {
        old_values.push(&init_values[i]);
    }

    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(prove_from_scratch(&params, &old_values, i));
    }
    // Copy over the proof of the updated value in order to avoid mutable borrow isues in the proof_update
    let mut proof_of_updated_value = vec![0u8; proofs[update_index].len()];
    proof_of_updated_value.copy_from_slice(&proofs[update_index]);

    let new_value = format!("this is new message number {}", update_index).into_bytes();

    let mut i: usize = 0;
    b.iter(|| {
        proof_update(
            &params,
            &mut proofs[i],
            i,
            update_index,
            &proof_of_updated_value,
            &new_value,
            None,
        );
        i = (i + 1) % n;
        if i == update_index {
            // skip update_index
            i = (i + 1) % n;
        }
        proofs[i].len();
    });
}

fn bench_proof_update_with_helper_merkle(b: &mut Bencher) {
    let n = 1000usize;
    let update_index = n / 2; // We will update message number n/2 and then benchmark changing proofs for others

    let params = paramgen(n);

    let mut init_values = Vec::with_capacity(n);
    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);

    for i in 0..n {
        let s = format!("this is old message number {}", i);
        init_values.push(s.into_bytes());
    }
    for i in 0..n {
        old_values.push(&init_values[i]);
    }

    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(prove_from_scratch(&params, &old_values, i));
    }
    // Copy over the proof of the updated value in order to avoid mutable borrow isues in the proof_update
    let mut proof_of_updated_value = vec![0u8; proofs[update_index].len()];
    proof_of_updated_value.copy_from_slice(&proofs[update_index]);

    let new_value = format!("this is new message number {}", update_index).into_bytes();

    let helper_info = commit_update(&params, update_index, &proof_of_updated_value, &new_value).1;

    let mut i: usize = 0;
    b.iter(|| {
        proof_update(
            &params,
            &mut proofs[i],
            i,
            update_index,
            &proof_of_updated_value,
            &new_value,
            Some(&helper_info),
        );
        i = (i + 1) % n;
        if i == update_index {
            // skip update_index
            i = (i + 1) % n;
        }
        proofs[i].len()
    });
}
