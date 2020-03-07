use crate::pairings::*;
use ff::{Field, PrimeField};
use pairing::{bls12_381::*, CurveAffine, CurveProjective};
use pairings::param::paramgen_from_seed;
use rand_core::SeedableRng;
use std::sync::{Arc, Mutex};
use std::thread;

#[test]
fn test_ms() {
    let mut rng = rand_xorshift::XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let v = vec![VeccomG1::random(&mut rng).into_affine(); 16];
    let fr = vec![Fr::random(&mut rng).into_repr(); 16];
    let fr1 = fr[0..8].to_vec();
    let fr2 = fr[8..16].to_vec();
    let v1 = v[0..8].to_vec();
    let v2 = v[8..16].to_vec();
    let fr_u64: Vec<&[u64; 4]> = fr.iter().map(|x| &x.0).collect();
    let res = VeccomG1Affine::sum_of_products(&v[..], &fr_u64);
    let mut handles = vec![];

    let buf = Arc::new(Mutex::new(vec![]));
    let t = vec![(v1, fr1), (v2, fr2)];
    for (vi, fri) in t {
        let buf_local = Arc::clone(&buf);
        let handle = thread::spawn(move || {
            let fri_u64: Vec<&[u64; 4]> = fri.iter().map(|x| &x.0).collect();
            let mut v = buf_local.lock().unwrap();
            v.push(VeccomG1Affine::sum_of_products(&vi[..], &fri_u64));
        });
        handles.push(handle);
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let buf_unwrap = &*buf.lock().unwrap();
    let mut res2 = G1::zero();
    for e in buf_unwrap {
        res2.add_assign(&e);
    }

    assert_eq!(res, res2);
}

#[test]
fn test_ms_commit() {
    let n = 16usize;
    let thd_array = [1, 2, 3, 4];
    let (prover_params, _verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_values.iter().take(n) {
        values.push(&e);
    }

    for i in 0..n {
        let proof = Proof::new(&prover_params, &values, i).unwrap();
        for num_thd in thd_array.iter() {
            assert_eq!(
                proof,
                Proof::new_mt(&prover_params, &values, i, *num_thd).unwrap()
            );
        }
    }
}
