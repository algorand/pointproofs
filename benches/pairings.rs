#[macro_use]
extern crate bencher;
extern crate veccom;

use bencher::Bencher;
use veccom::pairings::paramgen::*;
use veccom::pairings::commit::*;
use veccom::pairings::verify::*;
use veccom::pairings::prove::*;

benchmark_group!(benches, bench_com, bench_prove, bench_verify, bench_commit_update, bench_proof_update);
benchmark_main!(benches);

// Does not include a to_bytes conversion for the commitment, because you normally
// would store this yourself rather than send it on the network
fn bench_com(b: &mut Bencher) {
    let n = 1000usize;

    let prover_params = paramgen_from_seed(&format!("This is Leo's Favourite Seed").into_bytes(), n).0;

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(&init_values[i]);
    }
    
    b.iter(||{
        commit(&prover_params, &values)
    });
}

// includes to_bytes conversion for the proof, because this is supposed to measure what it takes
// to produce a proof you will send on the network
fn bench_prove(b: &mut Bencher) {
    let n = 1000usize;

    let prover_params = paramgen_from_seed(&format!("This is Leo's Favourite Seed").into_bytes(), n).0;

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let mut i : usize = 0;
    b.iter(|| {
        let p = convert_proof_to_bytes(&prove(&prover_params, &values, i));
        i = (i+1)%n;
        p
    });
}

// includes from_bytes conversion for the proof, because you would normally get the proof from the network
fn bench_verify(b: &mut Bencher) {
    let n = 1000usize;

    let (prover_params, verifier_params) = paramgen_from_seed(&format!("This is Leo's Favourite Seed").into_bytes(), n);

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        values.push(&init_values[i]);
    }

    let com = commit(&prover_params, &values);
    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(convert_proof_to_bytes(&prove(&prover_params, &values, i)));
    }

    let mut i : usize = 0;
    b.iter(|| {
        assert!(verify(&verifier_params, &com, &convert_bytes_to_proof(&proofs[i]), &values[i], i));
        i = (i+1)%n;
    });
}

// Does not include to/from bytes conversion, because this is supposed to be a local operation
fn bench_commit_update(b: &mut Bencher) {
    let n = 1000usize;

    let prover_params = paramgen_from_seed(&format!("This is Leo's Favourite Seed").into_bytes(), n).0;

    let mut init_old_values = Vec::with_capacity(n);
    let mut init_new_values = Vec::with_capacity(n);
    let mut old_value = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is old message number {}", i);
        init_old_values.push(s.into_bytes());
        let t = format!("this is new message number {}", i);
        init_new_values.push(t.into_bytes());
        old_value.push(true);
    }

    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);
    let mut new_values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        old_values.push(&init_old_values[i]);
        new_values.push(&init_new_values[i]);
    }

    let mut com = commit(&prover_params, &old_values);
    let mut i : usize = 0;
    b.iter(|| {
        commit_update(&prover_params, &com, i, &old_values[i], &new_values[i]);
        old_value[i] = !old_value[i];
        i = (i+1)%n;
    });
}

// Does not include to/from bytes conversion, because this is supposed to be a local operation
fn bench_proof_update(b: &mut Bencher) {
    let n = 1000usize;
    let update_index = n/2;  // We will update message number n/2 and then benchmark changing proofs for others

    let prover_params = paramgen_from_seed(&format!("This is Leo's Favourite Seed").into_bytes(), n).0;

    let mut init_old_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is old message number {}", i);
        init_old_values.push(s.into_bytes());
    }

    let mut old_values: Vec<&[u8]> = Vec::with_capacity(n);
    for i in 0..n {
        old_values.push(&init_old_values[i]);
    }

    let mut proofs = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(prove(&prover_params, &old_values, i));
    }

    let new_value = format!("this is new message number {}", update_index).into_bytes();
    
    let mut i : usize = 0;
    b.iter(|| {
        let new_proof = proof_update(&prover_params, &proofs[i], i, update_index, &old_values[update_index], &new_value);
        i = (i+1)%n;
        if i==update_index { // skip update_index
            i = (i+1)%n;
        }
        new_proof
    });
}
