use pairings::c_api::*;
use pairings::*;

#[test]
fn test_c_api_basic() {
    let n = 1024;
    let seed = "This is Leo's Favourite very very very long Seed";
    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values: Vec<vcp_value> = vec![];
    for e in init_values.iter().take(n) {
        values.push(vcp_value {
            data: e.as_ptr(),
            len: e.len(),
        });
    }

    unsafe {
        let param = vcp_paramgen(seed.as_ptr(), seed.len(), 0, n);
        let pp_bytes = vcp_pp_serial(param.prover);
        let vp_bytes = vcp_vp_serial(param.verifier);
        let pp = vcp_pp_deserial(pp_bytes);
        let vp = vcp_vp_deserial(vp_bytes);

        let com = vcp_commit(pp.clone(), values.as_ptr(), n);
        let com_bytes = vcp_commit_serial(com.clone());
        let com_rec = vcp_commit_deserial(com_bytes.clone());
        let com_bytes_rec = vcp_commit_serial(com_rec);
        for i in 0..COMMIT_LEN {
            assert_eq!(com_bytes.data[i], com_bytes_rec.data[i]);
        }

        let proof = vcp_prove(pp.clone(), values.as_ptr(), n, 0);
        let proof_bytes = vcp_proof_serial(proof.clone());
        let proof_rec = vcp_proof_deserial(proof_bytes.clone());
        let proof_bytes_rec = vcp_proof_serial(proof_rec);
        for i in 0..PROOF_LEN {
            assert_eq!(proof_bytes.data[i], proof_bytes_rec.data[i]);
        }

        assert!(vcp_verify(
            vp.clone(),
            com.clone(),
            proof.clone(),
            values[0].clone(),
            0
        ));

        let new_com = vcp_commit_update(pp.clone(), com, 1, values[1].clone(), values[0].clone());
        let new_proof = vcp_proof_update(pp, proof, 0, 1, values[1].clone(), values[0].clone());
        assert!(vcp_verify(vp, new_com, new_proof, values[0].clone(), 0));
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

    let mut values1: Vec<vcp_value> = vec![];
    for e in init_values.iter().take(n) {
        values1.push(vcp_value {
            data: e.as_ptr(),
            len: e.len(),
        });
    }

    let mut init_values = Vec::with_capacity(n);
    for i in 0..n {
        let s = format!("this is another message number {}", i);
        init_values.push(s.into_bytes());
    }

    let mut values2: Vec<vcp_value> = vec![];
    for e in init_values.iter().take(n) {
        values2.push(vcp_value {
            data: e.as_ptr(),
            len: e.len(),
        });
    }

    unsafe {
        let param = vcp_paramgen(seed.as_ptr(), seed.len(), 0, n);

        let pp = param.prover;
        let vp = param.verifier;

        let com1 = vcp_commit(pp.clone(), values1.as_ptr(), n);
        let com2 = vcp_commit(pp.clone(), values2.as_ptr(), n);

        let proof10 = vcp_prove(pp.clone(), values1.as_ptr(), n, 0);
        let proof11 = vcp_prove(pp.clone(), values1.as_ptr(), n, 1);
        let proof20 = vcp_prove(pp.clone(), values2.as_ptr(), n, 0);
        let proof21 = vcp_prove(pp.clone(), values2.as_ptr(), n, 1);

        let agg_proof = vcp_x_commit_aggregate_full(
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
        );

        assert!(vcp_x_commit_batch_verify(
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

        let agg_proof1 = vcp_same_commit_aggregate(
            com1.clone(),
            [proof10, proof11].as_ptr(),
            [0, 1].as_ptr(),
            [values1[0].clone(), values1[1].clone()].as_ptr(),
            2,
            n,
        );
        let agg_proof11 =
            vcp_prove_batch_aggregated(pp.clone(), com1.clone(), values1.as_ptr(), n, &[0, 1]);
        let proof_bytes1 = vcp_proof_serial(agg_proof1.clone());
        let proof_bytes11 = vcp_proof_serial(agg_proof11.clone());
        for i in 0..PROOF_LEN {
            assert_eq!(proof_bytes1.data[i], proof_bytes11.data[i]);
        }

        let agg_proof2 = vcp_same_commit_aggregate(
            com2.clone(),
            [proof20, proof21].as_ptr(),
            [0, 1].as_ptr(),
            [values2[0].clone(), values2[1].clone()].as_ptr(),
            2,
            n,
        );

        assert!(vcp_same_commit_batch_verify(
            vp.clone(),
            com1.clone(),
            agg_proof1.clone(),
            [0, 1].as_ptr(),
            [values1[0].clone(), values1[1].clone()].as_ptr(),
            2,
        ));

        assert!(vcp_same_commit_batch_verify(
            vp.clone(),
            com2.clone(),
            agg_proof2.clone(),
            [0, 1].as_ptr(),
            [values2[0].clone(), values2[1].clone()].as_ptr(),
            2,
        ));

        let agg_proof_new = vcp_x_commit_aggregate_partial(
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
        );

        assert!(vcp_x_commit_batch_verify(
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
