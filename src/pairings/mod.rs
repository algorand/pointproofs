use pairing::{bls12_381::*};


pub struct ProverParams {
    generators : Vec<G1>
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
    use test::Bencher;

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
    fn test_com() {
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

        // Check all proofs, together with conversion to/from bytes
        for i in 0..n {
            proofs.push (prove(&prover_params, &values, i));
            let wrong_string = format!("wrong string {}", i).into_bytes();
            let proof_bytes = convert_proof_to_bytes(&proofs[i]);
            assert!(verify(&verifier_params, &com, &convert_bytes_to_proof(&proof_bytes), &values[i], i));
            assert!(!verify(&verifier_params, &com, &convert_bytes_to_proof(&proof_bytes), &wrong_string, i));
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

    
    #[bench]
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
        
        b.iter(|| { 
            commit(&prover_params, &values)
        });
    }

    #[bench]
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

    #[bench]
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

    #[bench]
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

    #[bench]
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

}
