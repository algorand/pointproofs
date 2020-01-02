use pairings::param::paramgen_from_seed;
use pairings::*;

#[test]
fn negative_test_commit() {
    let n = 8usize;
    let (prover_params, _verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();
    let mut prover_params2 = prover_params.clone();
    prover_params2.ciphersuite = 1;

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_values.iter().take(n) {
        values.push(&e);
    }
    let mut new_values = Vec::with_capacity(n);
    for i in 0..n {
        new_values.push(format!("new string {}", i).into_bytes());
    }

    let com_res = Commitment::new(&prover_params2, &values);
    assert!(com_res.is_err());

    let mut values2: Vec<&[u8]> = Vec::with_capacity(n);
    values2.push(&init_values[0]);
    let com_res = Commitment::new(&prover_params, &values2);
    assert!(com_res.is_err());

    let mut com = Commitment::new(&prover_params, &values).unwrap();
    assert!(com
        .update(&prover_params, n, &values[0], &new_values[0][..].as_ref())
        .is_err());

    assert!(com
        .update(&prover_params2, 0, &values[0], &new_values[0][..].as_ref())
        .is_err());

    com.ciphersuite = 1;
    assert!(com
        .update(&prover_params2, 0, &values[0], &new_values[0][..].as_ref())
        .is_err());
}

#[test]
fn test_commit() {
    let n = 8usize;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();

    let mut prover_params3 = prover_params.clone();
    prover_params3.precomp_3();

    let mut prover_params256 = prover_params.clone();
    prover_params256.precomp_256();

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_values.iter().take(n) {
        values.push(&e);
    }

    let mut com = Commitment::new(&prover_params, &values).unwrap();
    assert_eq!(com, Commitment::new(&prover_params3, &values).unwrap());
    assert_eq!(com, Commitment::new(&prover_params256, &values).unwrap());
    let mut proofs = Vec::with_capacity(n);

    // Check all proofs, together with conversion to/from bytes
    for i in 0..n {
        proofs.push(Proof::new(&prover_params, &values, i).unwrap());
        assert_eq!(proofs[i], Proof::new(&prover_params3, &values, i).unwrap());
        assert_eq!(
            proofs[i],
            Proof::new(&prover_params256, &values, i).unwrap()
        );
    }

    // update values
    let mut new_values = Vec::with_capacity(n);
    for i in 0..n {
        new_values.push(format!("new string {}", i).into_bytes());
    }
    for i in 0..n {
        let mut com3 = com.clone();
        let mut com256 = com.clone();
        com.update(&prover_params, i, &values[i], &new_values[i][..].as_ref())
            .unwrap();
        com3.update(&prover_params3, i, &values[i], &new_values[i][..].as_ref())
            .unwrap();
        com256
            .update(
                &prover_params256,
                i,
                &values[i],
                &new_values[i][..].as_ref(),
            )
            .unwrap();

        assert_eq!(com, com3);
        assert_eq!(com, com256);

        // Old value should not verify, but new one should
        assert!(!proofs[i].verify(&verifier_params, &com, &values[i], i));
        assert!(proofs[i].verify(&verifier_params, &com, &new_values[i], i));

        // update proofs of other values
        for j in 0..n {
            // Old proofs should not verify for i!=j regardless of whether they are for the old or the new value
            if i != j {
                assert!(!proofs[j].verify(&verifier_params, &com, &values[j], j));
                assert!(!proofs[j].verify(&verifier_params, &com, &new_values[j], j));
            }
            let mut proof3 = proofs[j].clone();
            let mut proof256 = proofs[j].clone();
            proofs[j]
                .update(
                    &prover_params,
                    j,
                    i,
                    &values[i],
                    &new_values[i][..].as_ref(),
                )
                .unwrap();
            proof3
                .update(
                    &prover_params3,
                    j,
                    i,
                    &values[i],
                    &new_values[i][..].as_ref(),
                )
                .unwrap();
            proof256
                .update(
                    &prover_params256,
                    j,
                    i,
                    &values[i],
                    &new_values[i][..].as_ref(),
                )
                .unwrap();

            assert_eq!(proofs[j], proof3);
            assert_eq!(proofs[j], proof256);
            if j <= i {
                assert!(proofs[j].verify(&verifier_params, &com, &new_values[j], j));
                assert!(!proofs[j].verify(&verifier_params, &com, &values[j], j));
            } else {
                assert!(!proofs[j].verify(&verifier_params, &com, &new_values[j], j));
                assert!(proofs[j].verify(&verifier_params, &com, &values[j], j));
            }
        }
    }
}

#[test]
#[ignore]
fn test_commit_full() {
    let n = 32usize;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, n).unwrap();

    let mut prover_params3 = prover_params.clone();
    prover_params3.precomp_3();

    let mut prover_params256 = prover_params.clone();
    prover_params256.precomp_256();

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<&[u8]> = Vec::with_capacity(n);
    for e in init_values.iter().take(n) {
        values.push(&e);
    }

    let mut com = Commitment::new(&prover_params, &values).unwrap();
    assert_eq!(com, Commitment::new(&prover_params3, &values).unwrap());
    assert_eq!(com, Commitment::new(&prover_params256, &values).unwrap());
    let mut proofs = Vec::with_capacity(n);

    // Check all proofs, together with conversion to/from bytes
    for i in 0..n {
        proofs.push(Proof::new(&prover_params, &values, i).unwrap());
        assert_eq!(proofs[i], Proof::new(&prover_params3, &values, i).unwrap());
        assert_eq!(
            proofs[i],
            Proof::new(&prover_params256, &values, i).unwrap()
        );
    }

    // update values
    let mut new_values = Vec::with_capacity(n);
    for i in 0..n {
        new_values.push(format!("new string {}", i).into_bytes());
    }
    for i in 0..n {
        let mut com3 = com.clone();
        let mut com256 = com.clone();
        com.update(&prover_params, i, &values[i], &new_values[i][..].as_ref())
            .unwrap();
        com3.update(&prover_params3, i, &values[i], &new_values[i][..].as_ref())
            .unwrap();
        com256
            .update(
                &prover_params256,
                i,
                &values[i],
                &new_values[i][..].as_ref(),
            )
            .unwrap();

        assert_eq!(com, com3);
        assert_eq!(com, com256);

        // Old value should not verify, but new one should
        assert!(!proofs[i].verify(&verifier_params, &com, &values[i], i));
        assert!(proofs[i].verify(&verifier_params, &com, &new_values[i], i));

        // update proofs of other values
        for j in 0..n {
            // Old proofs should not verify for i!=j regardless of whether they are for the old or the new value
            if i != j {
                assert!(!proofs[j].verify(&verifier_params, &com, &values[j], j));
                assert!(!proofs[j].verify(&verifier_params, &com, &new_values[j], j));
            }
            let mut proof3 = proofs[j].clone();
            let mut proof256 = proofs[j].clone();
            proofs[j]
                .update(
                    &prover_params,
                    j,
                    i,
                    &values[i],
                    &new_values[i][..].as_ref(),
                )
                .unwrap();
            proof3
                .update(
                    &prover_params3,
                    j,
                    i,
                    &values[i],
                    &new_values[i][..].as_ref(),
                )
                .unwrap();
            proof256
                .update(
                    &prover_params3,
                    j,
                    i,
                    &values[i],
                    &new_values[i][..].as_ref(),
                )
                .unwrap();

            assert_eq!(proofs[j], proof3);
            assert_eq!(proofs[j], proof256);
            if j <= i {
                assert!(proofs[j].verify(&verifier_params, &com, &new_values[j], j));
                assert!(!proofs[j].verify(&verifier_params, &com, &values[j], j));
            } else {
                assert!(!proofs[j].verify(&verifier_params, &com, &new_values[j], j));
                assert!(proofs[j].verify(&verifier_params, &com, &values[j], j));
            }
        }
    }
}
