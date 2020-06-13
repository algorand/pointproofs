use pairings::c_api::*;
use pairings::pointproofs_groups::*;

#[test]
fn test_c_api_basic() {
    let n = 1024;
    let seed = "This is Leo's Favourite very very very long Seed";
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<pointproofs_value> = vec![];
    for e in init_values.iter().take(n) {
        values.push(pointproofs_value {
            data: e.as_ptr(),
            len: e.len(),
        });
    }
    let mut param = pointproofs_params::default();
    let mut pp_bytes = pointproofs_pp_bytes::default();
    let mut pp = pointproofs_pp::default();
    let mut vp_bytes = pointproofs_vp_bytes::default();
    let mut vp = pointproofs_vp::default();
    let mut com = pointproofs_commitment::default();
    let mut com_rec = pointproofs_commitment::default();
    let mut com_bytes = pointproofs_commitment_bytes::default();
    let mut com_bytes_rec = pointproofs_commitment_bytes::default();
    let mut proof = pointproofs_proof::default();
    let mut proof_bytes = pointproofs_proof_bytes::default();
    let mut proof_rec = pointproofs_proof::default();
    let mut proof_bytes_rec = pointproofs_proof_bytes::default();
    let mut new_com = pointproofs_commitment::default();
    let mut new_proof = pointproofs_proof::default();
    unsafe {
        pointproofs_paramgen(seed.as_ptr(), seed.len(), 0, n, &mut param);
        pointproofs_pp_serial(param.prover, &mut pp_bytes);
        pointproofs_vp_serial(param.verifier, &mut vp_bytes);
        pointproofs_pp_deserial(pp_bytes, &mut pp);
        pointproofs_vp_deserial(vp_bytes, &mut vp);

        assert!(pointproofs_commit(pp.clone(), values.as_ptr(), n, &mut com) == 0);
        assert!(pointproofs_commit_serial(com.clone(), &mut com_bytes) == 0);
        assert!(pointproofs_commit_deserial(com_bytes.clone(), &mut com_rec) == 0);
        assert!(pointproofs_commit_serial(com_rec, &mut com_bytes_rec) == 0);
        for i in 0..COMMIT_LEN {
            assert_eq!(com_bytes.data.add(i).read(), com_bytes_rec.data.add(i).read());
        }

        assert!(pointproofs_prove(pp.clone(), values.as_ptr(), n, 0, &mut proof) == 0);
        assert!(pointproofs_proof_serial(proof.clone(), &mut proof_bytes) == 0);
        assert!(pointproofs_proof_deserial(proof_bytes.clone(), &mut proof_rec) == 0);
        assert!(pointproofs_proof_serial(proof_rec, &mut proof_bytes_rec) == 0);
        for i in 0..PROOF_LEN {
            assert_eq!(proof_bytes.data.add(i).read(), proof_bytes_rec.data.add(i).read());
        }

        assert!(pointproofs_verify(
            vp.clone(),
            com.clone(),
            proof.clone(),
            values[0].clone(),
            0
        ));

        assert!(
            pointproofs_commit_update(
                pp.clone(),
                com,
                1,
                values[1].clone(),
                values[0].clone(),
                &mut new_com,
            ) == 0
        );
        assert!(
            pointproofs_proof_update(
                pp,
                proof,
                0,
                1,
                values[1].clone(),
                values[0].clone(),
                &mut new_proof,
            ) == 0
        );
        assert!(pointproofs_verify(
            vp,
            new_com,
            new_proof,
            values[0].clone(),
            0
        ));
    }
}

#[test]
fn test_c_api_aggregate() {
    let n = 1024;
    let seed = "This is Leo's Favourite very very very long Seed";
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values1: Vec<pointproofs_value> = vec![];
    for e in init_values.iter().take(n) {
        values1.push(pointproofs_value {
            data: e.as_ptr(),
            len: e.len(),
        });
    }

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is another message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values2: Vec<pointproofs_value> = vec![];
    for e in init_values.iter().take(n) {
        values2.push(pointproofs_value {
            data: e.as_ptr(),
            len: e.len(),
        });
    }

    let mut param = pointproofs_params::default();

    let mut com1 = pointproofs_commitment::default();
    let mut com2 = pointproofs_commitment::default();
    let mut proof10 = pointproofs_proof::default();
    let mut proof11 = pointproofs_proof::default();
    let mut proof20 = pointproofs_proof::default();
    let mut proof21 = pointproofs_proof::default();

    let mut agg_proof11 = pointproofs_proof::default();
    let mut proof_bytes1 = pointproofs_proof_bytes::default();
    let mut proof_bytes11 = pointproofs_proof_bytes::default();
    let mut agg_proof = pointproofs_proof::default();
    let mut agg_proof1 = pointproofs_proof::default();
    let mut agg_proof2 = pointproofs_proof::default();
    let mut agg_proof_new = pointproofs_proof::default();
    unsafe {
        assert!(pointproofs_paramgen(seed.as_ptr(), seed.len(), 0, n, &mut param) == 0);

        let pp = param.prover;
        let vp = param.verifier;

        assert!(pointproofs_commit(pp.clone(), values1.as_ptr(), n, &mut com1) == 0);
        assert!(pointproofs_commit(pp.clone(), values2.as_ptr(), n, &mut com2) == 0);

        assert!(pointproofs_prove(pp.clone(), values1.as_ptr(), n, 0, &mut proof10) == 0);
        assert!(pointproofs_prove(pp.clone(), values1.as_ptr(), n, 1, &mut proof11) == 0);
        assert!(pointproofs_prove(pp.clone(), values2.as_ptr(), n, 0, &mut proof20) == 0);
        assert!(pointproofs_prove(pp.clone(), values2.as_ptr(), n, 1, &mut proof21) == 0);

        assert!(
            pointproofs_x_commit_aggregate_full(
                [com1.clone(), com2.clone()].as_ptr(),
                [
                    proof10.clone(),
                    proof11.clone(),
                    proof20.clone(),
                    proof21.clone(),
                ]
                .as_ptr(),
                [0, 1, 0, 1].as_ptr(),
                [
                    values1[0].clone(),
                    values1[1].clone(),
                    values2[0].clone(),
                    values2[1].clone(),
                ]
                .as_ptr(),
                [2, 2].as_ptr(),
                2,
                n,
                &mut agg_proof,
            ) == 0
        );

        assert!(pointproofs_x_commit_batch_verify(
            vp.clone(),
            [com1.clone(), com2.clone()].as_ptr(),
            agg_proof,
            [0, 1, 0, 1].as_ptr(),
            [
                values1[0].clone(),
                values1[1].clone(),
                values2[0].clone(),
                values2[1].clone(),
            ]
            .as_ptr(),
            [2, 2].as_ptr(),
            2,
        ));

        assert!(
            pointproofs_same_commit_aggregate(
                com1.clone(),
                [proof10, proof11].as_ptr(),
                [0, 1].as_ptr(),
                [values1[0].clone(), values1[1].clone()].as_ptr(),
                2,
                n,
                &mut agg_proof1,
            ) == 0
        );
        assert!(
            pointproofs_prove_batch_aggregated(
                pp,
                com1.clone(),
                values1.as_ptr(),
                n,
                &[0, 1],
                &mut agg_proof11,
            ) == 0
        );
        assert!(pointproofs_proof_serial(agg_proof1.clone(), &mut proof_bytes1) == 0);
        assert!(pointproofs_proof_serial(agg_proof11, &mut proof_bytes11) == 0);
        for i in 0..PROOF_LEN {
            assert_eq!(proof_bytes1.data.add(i).read(), proof_bytes11.data.add(i).read());
        }

        assert!(
            pointproofs_same_commit_aggregate(
                com2.clone(),
                [proof20, proof21].as_ptr(),
                [0, 1].as_ptr(),
                [values2[0].clone(), values2[1].clone()].as_ptr(),
                2,
                n,
                &mut agg_proof2,
            ) == 0
        );

        assert!(pointproofs_same_commit_batch_verify(
            vp.clone(),
            com1.clone(),
            agg_proof1.clone(),
            [0, 1].as_ptr(),
            [values1[0].clone(), values1[1].clone()].as_ptr(),
            2,
        ));

        assert!(pointproofs_same_commit_batch_verify(
            vp.clone(),
            com2.clone(),
            agg_proof2.clone(),
            [0, 1].as_ptr(),
            [values2[0].clone(), values2[1].clone()].as_ptr(),
            2,
        ));

        assert!(
            pointproofs_x_commit_aggregate_partial(
                [com1.clone(), com2.clone()].as_ptr(),
                [agg_proof1, agg_proof2].as_ptr(),
                [0, 1, 0, 1].as_ptr(),
                [
                    values1[0].clone(),
                    values1[1].clone(),
                    values2[0].clone(),
                    values2[1].clone(),
                ]
                .as_ptr(),
                [2, 2].as_ptr(),
                2,
                n,
                &mut agg_proof_new,
            ) == 0
        );

        assert!(pointproofs_x_commit_batch_verify(
            vp,
            [com1, com2].as_ptr(),
            agg_proof_new,
            [0, 1, 0, 1].as_ptr(),
            [
                values1[0].clone(),
                values1[1].clone(),
                values2[0].clone(),
                values2[1].clone(),
            ]
            .as_ptr(),
            [2, 2].as_ptr(),
            2,
        ));
    }
}
