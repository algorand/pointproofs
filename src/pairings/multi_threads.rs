// use ff::{Field, PrimeField};
use pairing::{bls12_381::*, CurveAffine, CurveProjective};
use pairings::err::*;
use pairings::hash_to_field_veccom::*;
use pairings::param::*;
use pairings::*;
use std::sync::{Arc, Mutex};
use std::thread;
impl Proof {
    pub fn new_mt<Blob: AsRef<[u8]>>(
        prover_params: &ProverParams,
        values: &[Blob],
        index: usize,
        num_thd: usize,
    ) -> Result<Self, String> {
        // checks that cipersuite is supported
        if !check_ciphersuite(prover_params.ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }

        // check index is valid
        if index >= prover_params.n {
            return Err(ERR_INVALID_INDEX.to_owned());
        };
        // check param
        if values.len() != prover_params.n {
            return Err(ERR_INVALID_INDEX.to_owned());
        }

        // hash into a set of scalars
        let scalars_fr_repr: Vec<FrRepr> = values
            .iter()
            .map(|s| hash_to_field_repr_veccom(&s.as_ref()))
            .collect();

        // build inputs to the threads
        // each thread (except the last one) takes `batch` pairs of G1 and Fr elements
        let batch = prover_params.n / num_thd;
        let mut threads: Vec<(Vec<G1Affine>, Vec<FrRepr>)> = Vec::with_capacity(num_thd);
        for i in 0..num_thd - 1 {
            threads.push((
                prover_params.generators[(prover_params.n - index + i * batch)
                    ..(prover_params.n - index + (i + 1) * batch)]
                    .to_vec(),
                scalars_fr_repr[(i * batch)..(i + 1) * batch].to_vec(),
            ));
        }

        // the last thread contains the rest
        threads.push((
            prover_params.generators
                [(prover_params.n - index + (num_thd - 1) * batch)..(2 * prover_params.n - index)]
                .to_vec(),
            scalars_fr_repr[((num_thd - 1) * batch)..prover_params.n].to_vec(),
        ));

        // handles handles the results that are returnd to the shared_buf
        let mut handles = Vec::with_capacity(num_thd);
        let shared_buf = Arc::new(Mutex::new(Vec::with_capacity(num_thd)));

        // begin threading
        for (basis_local, scalar_local) in threads {
            let buf_local = Arc::clone(&shared_buf);
            let handle = thread::spawn(move || {
                // each thread does the sum of product locally
                let fr_u64: Vec<&[u64; 4]> = scalar_local.iter().map(|x| &x.0).collect();
                let tmp = G1Affine::sum_of_products(&basis_local[..], &fr_u64);

                // return the result to shared buf
                let mut v = buf_local.lock().unwrap();
                v.push(tmp);
            });
            handles.push(handle);
        }
        // synch the threads
        for handle in handles {
            handle.join().unwrap();
        }
        let buf_unwrap = &*shared_buf.lock().unwrap();

        // sum the threads' outputs together to get the final result
        let mut proof = VeccomG1::zero();
        for e in buf_unwrap {
            proof.add_assign(&e);
        }
        Ok(Self {
            ciphersuite: prover_params.ciphersuite,
            proof,
        })
    }
}
