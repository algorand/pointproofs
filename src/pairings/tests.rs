use self::ciphersuite::get_system_paramter;
use super::commit::update_to_zero_hash;
use super::verify::verify_hash_inverse;
use super::*;
use super::{Commitment, Proof};
use ff::Field;
use pairing::{serdes::SerDes, CurveProjective, Engine};

#[test]
fn test_paramgen() {
    let sp = get_system_paramter(0).unwrap();
    let n = sp.n;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0).unwrap();
    // prover_params.generators[i] should contain the generator of the G1 group raised to the power alpha^{i+1},
    // except prover_params.generators[n] will contain nothing useful.
    // verifier_params.generators[j] should contain the generator of the G2 group raised to the power alpha^{j+1}.
    // gt should contain the generator of the target group raised to the power alpha^{n+1}.

    let mut dh_values = Vec::with_capacity(3 * n);
    // If all is correct, then
    // dh_values[i] will contains the generator of the target group raised to the power alpha^{i+1}
    // We will test all possible pairing of the two arrays with each other and with the generators
    // of the two groups, and see if they all match as appropriate.

    for i in 0..n {
        dh_values.push(Bls12::pairing(prover_params.generators[i], G2::one()));
    }
    dh_values.push(verifier_params.gt_elt);
    for i in n + 1..2 * n {
        dh_values.push(Bls12::pairing(prover_params.generators[i], G2::one()));
    }
    for i in 0..n {
        dh_values.push(Bls12::pairing(
            prover_params.generators[2 * n - 1],
            verifier_params.generators[i],
        ));
    }

    for (i, e) in dh_values.iter().enumerate().take(n) {
        assert_eq!(e, &Bls12::pairing(G1::one(), verifier_params.generators[i]));
    }

    for i in 0..2 * n {
        if i != n {
            for j in 0..n {
                assert_eq!(
                    dh_values[i + j + 1],
                    Bls12::pairing(prover_params.generators[i], verifier_params.generators[j])
                );
            }
        }
    }
}

#[test]
fn test_com_pairings() {
    let sp = get_system_paramter(0).unwrap();
    let n = sp.n;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0).unwrap();

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

    let mut com_bytes: Vec<u8> = vec![];
    assert!(com.serialize(&mut com_bytes, true).is_ok());
    assert_eq!(
        com,
        Commitment::deserialize(&mut com_bytes[..].as_ref(), true).unwrap()
    );

    // put garbage into commitment bytes -- it should not crash
    com_bytes[0] = 6u8;
    com_bytes[1] = 17u8;
    com_bytes[2] = 20u8;
    com_bytes[3] = 9u8;
    assert!(Commitment::deserialize(&mut com_bytes[..].as_ref(), true).is_err());

    // Check all proofs, together with conversion to/from bytes
    for i in 0..n {
        proofs.push(Proof::new(&prover_params, &values, i).unwrap());
        assert_eq!(proofs[i], Proof::new(&prover_params3, &values, i).unwrap());
        assert_eq!(
            proofs[i],
            Proof::new(&prover_params256, &values, i).unwrap()
        );
        let mut buf: Vec<u8> = vec![];
        assert!(proofs[i].serialize(&mut buf, true).is_ok());
        let proof_recover = Proof::deserialize(&mut buf[..].as_ref(), true).unwrap();

        assert!(proof_recover.verify(&verifier_params, &com, &values[i], i));
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
        // update commitment to a value whose hash is 0 and see if correct proof verifies while wrong proof doesn't
        // this is done separately to test verification, because verification includes inverting the hash
        let temp_com = update_to_zero_hash(&prover_params, &com, i, &new_values[i]);
        // The old proof should verify
        assert!(verify_hash_inverse(
            &verifier_params,
            &temp_com.commit,
            &proofs[i].proof,
            None,
            i
        ));
        // put some into hash_inverse -- it should not verify
        assert!(!verify_hash_inverse(
            &verifier_params,
            &temp_com.commit,
            &proofs[i].proof,
            Some(Fr::one()),
            i
        ));
    }
}

#[test]
fn test_serdes_prover_param() {
    let (mut prover_params, _verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0).unwrap();

    let mut buf: Vec<u8> = vec![];
    assert!(prover_params.serialize(&mut buf, true).is_ok());

    let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
    assert_eq!(prover_params, prover_params_recover);

    prover_params.precomp_3();

    let mut buf: Vec<u8> = vec![];
    assert!(prover_params.serialize(&mut buf, true).is_ok());
    println!("{:02x?}", buf);

    let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
    assert_eq!(prover_params, prover_params_recover);

    prover_params.precomp_256();

    let mut buf: Vec<u8> = vec![];
    assert!(prover_params.serialize(&mut buf, true).is_ok());
    println!("{:02x?}", buf);

    let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
    assert_eq!(prover_params, prover_params_recover);
}

#[test]
fn test_serdes_verifier_param() {
    let (_prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0).unwrap();

    let mut buf: Vec<u8> = vec![];
    assert!(verifier_params.serialize(&mut buf, true).is_ok());

    let verifier_params_recover = VerifierParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
    assert_eq!(verifier_params, verifier_params_recover);
}

#[test]
fn test_aggregation() {
    let sp = get_system_paramter(0).unwrap();
    let n = sp.n;
    let (prover_params, verifier_params) =
        paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0).unwrap();

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

    let com = Commitment::new(&prover_params, &values).unwrap();

    let set = vec![1usize, 4, 7];
    let mut proofs: Vec<Proof> = vec![];

    for index in &set {
        let proof = Proof::new(&prover_params, &values, *index).unwrap();
        proofs.push(proof);
    }

    let agg_proof = Proof::aggregate(&com, &proofs, &set, &values).unwrap();
    assert!(agg_proof.batch_verify(&verifier_params, &com, &set, &values));

    let new_set = vec![1usize, 4, 8];
    assert!(!agg_proof.batch_verify(&verifier_params, &com, &new_set, &values));
}
