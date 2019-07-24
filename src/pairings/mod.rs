use pairing::{bls12_381::*};

pub struct ProverParams {
    generators : Vec<G1>,
    precomp : Option<Vec<[G1; 3]>>
}


pub struct VerifierParams {
    generators: Vec<G2>,
    gt_elt: Fq12
}

pub mod paramgen;
pub mod commit;
pub mod prove;
pub mod verify;
pub mod c_api;

#[cfg(test)]
mod tests {
    use pairing::{bls12_381::*, CurveProjective, Engine};
    use super::paramgen::*;
    use super::commit::*;
    use super::verify::*;
    use super::prove::*;

    #[test]
    fn test_paramgen() {
        let n = 10usize;
        let (prover_params, verifier_params) = paramgen_from_seed(&format!("This is Leo's Favourite Seed").into_bytes(), n);
        // prover_params.generators[i] should contain the generator of the G1 group raised to the power alpha^{i+1},
        // except prover_params.generators[n] will contain nothing useful.
        // verifier_params.generators[j] should contain the generator of the G2 group raised to the power alpha^{j+1}.
        // gt should contain the generator of the target group raised to the power alpha^{n+1}.

        let mut dh_values = Vec::with_capacity(3*n);
        // If all is correct, then
        // dh_values[i] will contains the generator of the target group raised to the power alpha^{i+1}
        // We will test all possible pairing of the two arrays with each other and with the generators
        // of the two groups, and see if they all match as appropriate.

        for i in 0..n {
            dh_values.push(Bls12::pairing(prover_params.generators[i], G2::one()));
        }
        dh_values.push(verifier_params.gt_elt);
        for i in n+1..2*n {
            dh_values.push(Bls12::pairing(prover_params.generators[i], G2::one()));
        }
        for i in 0..n {
            dh_values.push(Bls12::pairing(prover_params.generators[2*n-1], verifier_params.generators[i]));
        }

        for i in 0..n {
            assert_eq!(dh_values[i], Bls12::pairing(G1::one(), verifier_params.generators[i]));
        }

        for i in 0..2*n {
            if i!=n {
                for j in 0..n {
                    assert_eq!(dh_values[i+j+1], Bls12::pairing(prover_params.generators[i], verifier_params.generators[j]));
                }
            }
        }
    }

    #[test]
    fn test_com_no_precomp() {
        let n = 10usize;
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
        
        let mut com = commit(&prover_params, &values);
        let mut proofs = Vec::with_capacity(n);

        let mut com_bytes = convert_commitment_to_bytes(&com);
        assert_eq!(com, convert_bytes_to_commitment(&com_bytes));

        // put garbage into commitment bytes -- it should not crash
        com_bytes[0]=6u8;
        com_bytes[1]=17u8;
        com_bytes[2]=20u8;
        com_bytes[3]=9u8;
        assert_ne!(com, convert_bytes_to_commitment(&com_bytes));

        // Check all proofs, together with conversion to/from bytes
        for i in 0..n {
            proofs.push (prove(&prover_params, &values, i));
            let wrong_string = format!("wrong string {}", i).into_bytes();
            let mut proof_bytes = convert_proof_to_bytes(&proofs[i]);
            assert!(verify(&verifier_params, &com, &convert_bytes_to_proof(&proof_bytes), &values[i], i));
            assert!(!verify(&verifier_params, &com, &convert_bytes_to_proof(&proof_bytes), &wrong_string, i));

            // put garbage into proof bytes -- it should not verify
            proof_bytes[0]=7u8;
            proof_bytes[1]=4u8;
            proof_bytes[2]=17u8;
            proof_bytes[3]=76u8;
            assert!(!verify(&verifier_params, &com, &convert_bytes_to_proof(&proof_bytes), &values[i], i));            
        }

        // update values
        let mut new_values = Vec::with_capacity(n);
        for i in 0..n {
            new_values.push (format!("new string {}", i).into_bytes());
        }
        for i in 0..n {
            com = commit_update(&prover_params, &com, i, &values[i], &new_values[i]);
            // Old value should not verify, but new one should
            assert!(!verify(&verifier_params, &com, &proofs[i], &values[i], i));
            assert!(verify(&verifier_params, &com, &proofs[i], &new_values[i], i));
            // update proofs of other values
            for j in 0..n {
                // Old proofs should not verify for i!=j regardless of whether they are for the old or the new value
                if i!=j {
                    assert!(!verify(&verifier_params, &com, &proofs[j], &values[j], j));
                    assert!(!verify(&verifier_params, &com, &proofs[j], &new_values[j], j));
                }
                proofs[j] = proof_update(&prover_params, &proofs[j], j, i, &values[i], &new_values[i]);
                if j<=i {
                    assert!(verify(&verifier_params, &com, &proofs[j], &new_values[j], j));
                    assert!(!verify(&verifier_params, &com, &proofs[j], &values[j], j));
                } else {
                    assert!(!verify(&verifier_params, &com, &proofs[j], &new_values[j], j));
                    assert!(verify(&verifier_params, &com, &proofs[j], &values[j], j));
                }
            }
        }
    }

    #[test]
    fn test_com_precomp() {
        let n = 10usize;
        let (mut prover_params, verifier_params) = paramgen_from_seed(&format!("This is Leo's Favourite Seed").into_bytes(), n);
        prover_params.precomp();

        let mut init_values = Vec::with_capacity(n);
        for i in 0..n {
            let s = format!("this is message number {}", i);
            init_values.push(s.into_bytes());
        }

        let mut values: Vec<&[u8]> = Vec::with_capacity(n);
        for i in 0..n {
            values.push(&init_values[i]);
        }
        
        let mut com = commit(&prover_params, &values);
        let mut proofs = Vec::with_capacity(n);

        let mut com_bytes = convert_commitment_to_bytes(&com);
        assert_eq!(com, convert_bytes_to_commitment(&com_bytes));

        // put garbage into commitment bytes -- it should not crash
        com_bytes[0]=6u8;
        com_bytes[1]=17u8;
        com_bytes[2]=20u8;
        com_bytes[3]=9u8;
        assert_ne!(com, convert_bytes_to_commitment(&com_bytes));

        // Check all proofs, together with conversion to/from bytes
        for i in 0..n {
            proofs.push (prove(&prover_params, &values, i));
            let wrong_string = format!("wrong string {}", i).into_bytes();
            let mut proof_bytes = convert_proof_to_bytes(&proofs[i]);
            assert!(verify(&verifier_params, &com, &convert_bytes_to_proof(&proof_bytes), &values[i], i));
            assert!(!verify(&verifier_params, &com, &convert_bytes_to_proof(&proof_bytes), &wrong_string, i));

            // put garbage into proof bytes -- it should not verify
            proof_bytes[0]=7u8;
            proof_bytes[1]=4u8;
            proof_bytes[2]=17u8;
            proof_bytes[3]=76u8;
            assert!(!verify(&verifier_params, &com, &convert_bytes_to_proof(&proof_bytes), &values[i], i));            
        }

        // update values
        let mut new_values = Vec::with_capacity(n);
        for i in 0..n {
            new_values.push (format!("new string {}", i).into_bytes());
        }
        for i in 0..n {
            com = commit_update(&prover_params, &com, i, &values[i], &new_values[i]);
            // Old value should not verify, but new one should
            assert!(!verify(&verifier_params, &com, &proofs[i], &values[i], i));
            assert!(verify(&verifier_params, &com, &proofs[i], &new_values[i], i));
            // update proofs of other values
            for j in 0..n {
                // Old proofs should not verify for i!=j regardless of whether they are for the old or the new value
                if i!=j {
                    assert!(!verify(&verifier_params, &com, &proofs[j], &values[j], j));
                    assert!(!verify(&verifier_params, &com, &proofs[j], &new_values[j], j));
                }
                proofs[j] = proof_update(&prover_params, &proofs[j], j, i, &values[i], &new_values[i]);
                if j<=i {
                    assert!(verify(&verifier_params, &com, &proofs[j], &new_values[j], j));
                    assert!(!verify(&verifier_params, &com, &proofs[j], &values[j], j));
                } else {
                    assert!(!verify(&verifier_params, &com, &proofs[j], &new_values[j], j));
                    assert!(verify(&verifier_params, &com, &proofs[j], &values[j], j));
                }
            }
        }
    }
}
