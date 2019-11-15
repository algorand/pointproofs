use super::ciphersuite::*;
use super::err::*;
use super::hash_to_field_veccom::{hash_to_field_veccom, hash_to_ti};
use super::{Commitment, Proof, ProverParams, VerifierParams};
use ff::{Field, PrimeField};
use pairings::hash_to_field_veccom::hash_to_field_repr_veccom;
//use pairing::hash_to_field::HashToField;
use pairing::serdes::SerDes;
use pairing::Engine;
use pairing::{bls12_381::*, CurveAffine, CurveProjective};
// impl std::cmp::PartialEq for Proof {
//     /// Convenient function to compare secret key objects
//     fn eq(&self, other: &Self) -> bool {
//         self.ciphersuite == other.ciphersuite
//             && self.proof == other.proof
//     }
// }

impl Proof {
    pub fn new<Blob: AsRef<[u8]>>(
        prover_params: &ProverParams,
        values: &[Blob],
        index: usize,
    ) -> Result<Self, String> {
        // implicitly checks that cipersuite is supported
        // let sp = get_system_paramter(prover_params.ciphersuite)?;
        assert!(
            check_ciphersuite(prover_params.ciphersuite),
            ERR_CIPHERSUITE.to_owned()
        );

        // check index is valid
        if index >= prover_params.n {
            return Err(ERR_INVALID_INDEX.to_owned());
        };

        Ok(Self {
            // FIXME: there is a potential mismatch of ciphersuite
            // prover_params.ciphersuite can be 0, 1, 2
            // while that of commitment and verifier_params are all 0
            ciphersuite: 0,
            proof: prove(prover_params, values, index),
        })
    }

    pub fn update<Blob: AsRef<[u8]>>(
        &mut self,
        prover_params: &ProverParams,
        proof_index: usize,
        changed_index: usize,
        value_before: Blob,
        value_after: Blob,
    ) -> Result<(), String> {
        // implicitly checks that cipersuite is supported
        // let sp = get_system_paramter(self.ciphersuite)?;
        assert!(
            check_ciphersuite(prover_params.ciphersuite),
            ERR_CIPHERSUITE.to_owned()
        );

        // check indices are valid
        if proof_index >= prover_params.n || changed_index >= prover_params.n {
            return Err(ERR_INVALID_INDEX.to_owned());
        }

        // update the proof
        self.proof = proof_update(
            prover_params,
            &self.proof,
            proof_index,
            changed_index,
            value_before.as_ref(),
            value_after.as_ref(),
        );
        Ok(())
    }

    pub fn verify<Blob: AsRef<[u8]>>(
        &self,
        verifier_params: &VerifierParams,
        com: &Commitment,
        value: Blob,
        index: usize,
    ) -> bool {
        if self.ciphersuite != verifier_params.ciphersuite || self.ciphersuite != com.ciphersuite {
            println!(
                " ciphersuite fails {}, {}, {}",
                self.ciphersuite, verifier_params.ciphersuite, com.ciphersuite
            );
            return false;
        }

        // implicitly checks that cipersuite is supported
        // let sp = match get_system_paramter(self.ciphersuite) {
        //     Err(e) => {
        //         println!("{}", e);
        //         return false;
        //     }
        //     Ok(p) => p,
        // };
        if !check_ciphersuite(com.ciphersuite) {
            return false;
        }

        if index >= verifier_params.n {
            println!("Invalid index");
            return false;
        }

        super::verify::verify(
            verifier_params,
            &com.commit,
            &self.proof,
            value.as_ref(),
            index,
        )
    }

    /// Aggregates a vector of commitments into a single one
    /// Note: the aggregator does not check the validity of
    /// individual commits. The caller may need to check them
    /// if they care for it.
    pub fn aggregate<Blob: AsRef<[u8]>>(
        commit: &Commitment,
        proofs: &[Self],
        set: &[usize],
        value_sub_vector: &[Blob],
        n: usize,
    ) -> Result<Self, String> {
        // check that the csids match
        let csid = proofs[0].ciphersuite;
        for e in proofs.iter().skip(0) {
            if e.ciphersuite != csid {
                return Err(ERR_CIPHERSUITE.to_owned());
            }
        }
        // check that the length of proofs and sets match
        if proofs.len() != set.len() || proofs.len() != value_sub_vector.len() {
            return Err(ERR_INDEX_PROOF_NOT_MATCH.to_owned());
        }
        // get the list of scalas
        let ti = hash_to_ti(commit, set, value_sub_vector, n)?;
        let scalars_u64: Vec<&[u64; 4]> = ti.iter().map(|s| &s.0).collect();
        let bases: Vec<G1Affine> = proofs.iter().map(|s| s.proof.into_affine()).collect();
        // proof = \prod proofs[i] ^ ti[i]
        let proof = G1Affine::sum_of_products(&bases[..], &scalars_u64);

        Ok(Proof {
            ciphersuite: csid,
            proof,
        })
    }

    pub fn batch_verify<Blob: AsRef<[u8]>>(
        &self,
        verifier_params: &VerifierParams,
        com: &Commitment,
        set: &[usize],
        value_sub_vector: &[Blob],
    ) -> bool {
        // we want to check if
        //   e(com, g2^{\sum_{i \in set} \alpha^{N+1-i} t_i})
        //    ?= e(proof, g2) * e(g1, g2)^{alpha^{N+1} \sum value_i*t_i}
        // which is to check
        //   e(com^tmp, g2^{\sum_{i \in set} \alpha^{N+1-i} t_i})
        //    * e(proof^{-tmp}, g2)
        //    ?= e(g1, g2)^{alpha^N+1}
        // where
        //   tmp = 1/ \sum value_i*t_i

        // 0. check the validity of the inputs: csid, length, etc
        // let sp = match get_system_paramter(self.ciphersuite) {
        //     Err(_e) => return false,
        //     Ok(p) => p,
        // };
        if !check_ciphersuite(com.ciphersuite) {
            return false;
        }
        if com.ciphersuite != verifier_params.ciphersuite {
            return false;
        }
        if set.len() != value_sub_vector.len() {
            return false;
        }
        if value_sub_vector.len() > verifier_params.n {
            return false;
        }
        for e in set {
            if *e >= verifier_params.n {
                return false;
            }
        }

        // 1. compute tmp
        // 1.1 get the list of scalas, return false if this failed
        let ti = match hash_to_ti(com, set, value_sub_vector, verifier_params.n) {
            Err(_e) => return false,
            Ok(p) => p,
        };

        // 1.2 tmp = 1/\sum value_i*t_i
        let mut tmp = Fr::zero();
        for i in 0..set.len() {
            let mut mi = hash_to_field_veccom(value_sub_vector[i].as_ref());
            let fr = match Fr::from_repr(ti[i]) {
                Ok(p) => p,
                Err(_e) => return false,
            };
            mi.mul_assign(&fr);
            tmp.add_assign(&mi);
        }

        // 1.3 if tmp == 0 (should never happen in practise)
        //  FIXME
        assert!(!tmp.is_zero());
        let mut tmp = tmp.inverse().unwrap();

        // 2 check
        //   e(com^tmp, g2^{\sum_{i \in set} \alpha^{N+1-i} t_i})
        //    * e(proof^{-tmp}, g2)
        //    ?= e(g1, g2)^{alpha^N+1}

        // 2.1 com ^ tmp
        let mut com_mut = com.commit;
        com_mut.mul_assign(tmp);

        // 2.2 g2^{\sum_{i \in set} \alpha^{N+1-i} t_i}

        let mut bases: Vec<G2Affine> = vec![];
        for index in set.iter().take(ti.len()) {
            bases.push(verifier_params.generators[verifier_params.n - index - 1]);
        }
        let scalars_u64: Vec<&[u64; 4]> = ti.iter().map(|s| &s.0).collect();
        let param_subset_sum = G2Affine::sum_of_products(&bases, &scalars_u64);

        // 2.3 proof ^ {-tmp}
        let mut proof_mut = self.proof;
        tmp.negate();
        proof_mut.mul_assign(tmp);

        // 3 pairing product
        Bls12::pairing_product(
            com_mut,
            param_subset_sum,
            proof_mut,
            G2Affine::one().into_projective(),
        ) == verifier_params.gt_elt
    }
}

type Compressed = bool;
impl SerDes for Proof {
    /// Convert a pop into a blob:
    ///
    /// `|ciphersuite id| commit |` => bytes
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        compressed: Compressed,
    ) -> std::io::Result<()> {
        // check the cipher suite id
        if !check_ciphersuite(self.ciphersuite) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_CIPHERSUITE,
            ));
        }
        let mut buf: Vec<u8> = vec![self.ciphersuite];
        self.proof.serialize(&mut buf, compressed)?;

        // format the output
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Convert a blob into a PoP:
    ///
    /// bytes => `|ciphersuite id | commit |`
    ///
    /// Returns an error if deserialization fails, or if
    /// the commit is not compressed.
    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        compressed: Compressed,
    ) -> std::io::Result<Self> {
        // constants stores id and the number of ssk-s
        let mut constants: [u8; 1] = [0u8; 1];

        reader.read_exact(&mut constants)?;

        // check the ciphersuite id in the blob
        if !check_ciphersuite(constants[0]) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_CIPHERSUITE,
            ));
        }

        // read into proof
        let proof = G1::deserialize(reader, compressed)?;

        // finished
        Ok(Proof {
            ciphersuite: constants[0],
            proof,
        })
    }
}

// #[allow(dead_code)]
// //#[cfg(test)]
// pub fn expose_get_ti_for_testing<Blob: AsRef<[u8]>>(
//     commit: &Commitment,
//     set: &[usize],
//     value_sub_vector: &[Blob],
// ) -> Result<Vec<FrRepr>, String> {
//     get_ti(commit, set, value_sub_vector)
// }
//
// // input: the commitment
// // input: a list of indices, for which we need to generate t_i
// // input: Value: the messages that is commited to
// // output: a list of field elements
// fn get_ti<Blob: AsRef<[u8]>>(
//     commit: &Commitment,
//     set: &[usize],
//     value_sub_vector: &[Blob],
// ) -> Result<Vec<FrRepr>, String> {
//     let sp = get_system_paramter(commit.ciphersuite)?;
//
//     // tmp = C | S | m[S]
//     let mut tmp: Vec<u8> = vec![];
//     // serialize commitment
//     match commit.serialize(&mut tmp, true) {
//         Ok(_p) => _p,
//         Err(e) => return Err(e.to_string()),
//     };
//     // add the set to tmp
//     for index in set {
//         let t = index.to_be_bytes();
//         tmp.append(&mut t.to_vec());
//     }
//
//     if set.len() != value_sub_vector.len() {
//         return Err(ERR_INDEX_PROOF_NOT_MATCH.to_owned());
//     }
//
//     // add values to set; returns an error if index is out of range
//     for i in 0..set.len() {
//         if set[i] >= sp.n {
//             return Err(ERR_INVALID_INDEX.to_owned());
//         }
//         let t = value_sub_vector[i].as_ref();
//         tmp.append(&mut t.to_vec());
//     }
//     // formulate the output
//     let mut res: Vec<FrRepr> = vec![];
//     for index in set {
//         // each field element t_i is generated as
//         // t_i = hash_to_field (i | C | S | m[S])
//         let mut hash_input: Vec<u8> = index.to_be_bytes().to_vec();
//         hash_input.append(&mut tmp.clone());
// //        let h2f = HashToField::new(hash_input, None);
// //        let fr: Fr = h2f.with_ctr(0);
//         res.push(hash_to_field_repr_veccom(hash_input));
//     }
//
//     Ok(res)
// }

/**
 * Assumes prover_params are correctly generated for n = values.len and that index<n
 */
fn prove<Blob: AsRef<[u8]>>(prover_params: &ProverParams, values: &[Blob], index: usize) -> G1 {
    let n = values.len();
    let scalars_fr_repr: Vec<FrRepr> = values
        .iter()
        .map(|s| {
            hash_to_field_repr_veccom(&s.as_ref())
            // HashToField::<Fr>::new(&s.as_ref(), None)
            //     .with_ctr(0)
            //     .into_repr()
        })
        .collect();
    let scalars_u64: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();
    if prover_params.precomp.len() == 512 * n {
        G1Affine::sum_of_products_precomp_256(
            &prover_params.generators[n - index..2 * n - index],
            &scalars_u64,
            &prover_params.precomp[(n - index) * 256..(2 * n - index) * 256],
        )
    } else {
        G1Affine::sum_of_products(
            &prover_params.generators[n - index..2 * n - index],
            &scalars_u64,
        )
    }
}

/**
 * For updating your proof when someone else's value changes
 * Not for updating your own proof when your value changes -- because then the proof does not change!
 * Assumes prover_params are correctly generated for n such that changed_index<n and proof_index<n
 */
fn proof_update(
    prover_params: &ProverParams,
    proof: &G1,
    proof_index: usize,
    changed_index: usize,
    value_before: &[u8],
    value_after: &[u8],
) -> G1 {
    let mut new_proof = *proof;

    if proof_index == changed_index {
        new_proof
    } else {
        let n = prover_params.generators.len() / 2;

        let mut multiplier = hash_to_field_veccom(&value_before);
        multiplier.negate();
        multiplier.add_assign(&hash_to_field_veccom(&value_after));

        let param_index = changed_index + n - proof_index;

        let res = if prover_params.precomp.len() == 6 * n {
            prover_params.generators[param_index].mul_precomp_3(
                multiplier,
                &prover_params.precomp[param_index * 3..(param_index + 1) * 3],
            )
        } else if prover_params.precomp.len() == 512 * n {
            prover_params.generators[param_index].mul_precomp_256(
                multiplier,
                &prover_params.precomp[param_index * 256..(param_index + 1) * 256],
            )
        } else {
            prover_params.generators[param_index].mul(multiplier)
        };

        new_proof.add_assign(&res);
        new_proof
    }
}
//
// /**
//  *  write a proof (which is a projective G1 element) into a 48-byte slice
//  */
// pub fn write_proof_into_slice(proof: &G1, out: &mut [u8]) {
//     let s = pairing::bls12_381::G1Compressed::from_affine(proof.into_affine());
//     out.copy_from_slice(s.as_ref());
// }
//
// /**
//  * Write a proof (which is a projective G1 element) into a 48-byte slice
//  * Copied from the bls library
//  */
// pub fn convert_proof_to_bytes(proof: &G1) -> [u8; 48] {
//     let s = pairing::bls12_381::G1Compressed::from_affine(proof.into_affine());
//     let mut out: [u8; 48] = [0; 48];
//     out.copy_from_slice(s.as_ref());
//     out
// }
//
// /**
//  * take an array of 48 bytes and output a proof
//  * Copied from the bls library
//  * In case bytes don't convert to a meaningful element of G1, defaults to the group generator
//  */
// pub fn convert_bytes_to_proof(input: &[u8]) -> G1 {
//     let mut proof_compressed = G1Compressed::empty();
//     proof_compressed.as_mut().copy_from_slice(input);
//     match proof_compressed.into_affine() {
//         Ok(proof_affine) => proof_affine.into_projective(),
//         Err(_) => G1::zero(),
//     }
// }
//
// /**
//  * take an array of 48 bytes and output a proof
//  * In case bytes don't convert to a meaningful element of G1,
//  * returns an error.
//  */
// pub fn convert_bytes_to_proof_err(input: &[u8]) -> Result<G1, GroupDecodingError> {
//     let mut proof_compressed = G1Compressed::empty();
//     proof_compressed.as_mut().copy_from_slice(input);
//     match proof_compressed.into_affine() {
//         Ok(proof_affine) => Ok(proof_affine.into_projective()),
//         Err(e) => Err(e),
//     }
// }
