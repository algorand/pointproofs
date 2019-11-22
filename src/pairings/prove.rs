use super::ciphersuite::*;
use super::err::*;
use super::hash_to_field_veccom::{
    hash_to_field_veccom, hash_to_ti_fr, hash_to_ti_repr, hash_to_tj,
};
use super::{Commitment, Proof, ProverParams, VerifierParams};
use ff::{Field, PrimeField};
use pairing::serdes::SerDes;
use pairing::Engine;
use pairing::{bls12_381::*, CurveAffine, CurveProjective};
use pairings::hash_to_field_veccom::hash_to_field_repr_veccom;
use pairings::*;

impl Proof {
    pub fn new<Blob: AsRef<[u8]>>(
        prover_params: &ProverParams,
        values: &[Blob],
        index: usize,
    ) -> Result<Self, String> {
        // checks that cipersuite is supported
        assert!(
            check_ciphersuite(prover_params.ciphersuite),
            ERR_CIPHERSUITE.to_owned()
        );

        // check index is valid
        if index >= prover_params.n {
            return Err(ERR_INVALID_INDEX.to_owned());
        };

        Ok(Self {
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
        // checks that cipersuite is supported
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

        if !check_ciphersuite(com.ciphersuite) {
            return false;
        }

        if index >= verifier_params.n {
            return false;
        }

        verify(
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
        let ti = hash_to_ti_repr(commit, set, value_sub_vector, n)?;
        let scalars_u64: Vec<&[u64; 4]> = ti.iter().map(|s| &s.0).collect();
        let bases: Vec<VeccomG1Affine> = proofs.iter().map(|s| s.proof.into_affine()).collect();
        // proof = \prod proofs[i] ^ ti[i]
        let proof = VeccomG1Affine::sum_of_products(&bases[..], &scalars_u64);

        Ok(Proof {
            ciphersuite: csid,
            proof,
        })
    }

    /// TODO: description
    pub fn cross_commit_aggregate<Blob: AsRef<[u8]>>(
        commits: &Vec<Commitment>,
        proofs: &Vec<Vec<Self>>,
        set: &Vec<Vec<usize>>,
        value_sub_vector: &Vec<Vec<Blob>>,
        n: usize,
    ) -> Result<Self, String> {
        // check the length are correct
        if commits.len() != proofs.len()
            || commits.len() != set.len()
            || commits.len() != value_sub_vector.len()
            || commits.len() == 0
        {
            println!(
                "commit: {}, proofs: {}, set: {}, value_sub_vector: {}",
                commits.len(),
                proofs.len(),
                set.len(),
                value_sub_vector.len()
            );
            return Err(ERR_X_COM_SIZE.to_owned());
        };

        // check ciphersuite
        let ciphersuite = commits[0].ciphersuite;
        if !check_ciphersuite(ciphersuite) {
            return Err(ERR_CIPHERSUITE.to_owned());
        }
        for e in commits.iter() {
            if e.ciphersuite != ciphersuite {
                return Err(ERR_CIPHERSUITE.to_owned());
            }
        }
        for e in proofs.iter() {
            for ee in e.iter() {
                if ee.ciphersuite != ciphersuite {
                    return Err(ERR_CIPHERSUITE.to_owned());
                }
            }
        }

        // if commit.len() == 1, call normal aggregation
        if commits.len() == 1 {
            return Self::aggregate(&commits[0], &proofs[0], &set[0], &value_sub_vector[0], n);
        }

        // start aggregation
        let scalars = hash_to_tj(&commits, &set, &value_sub_vector, n)?;

        let mut pi: Vec<Self> = vec![];
        for i in 0..commits.len() {
            pi.push(Self::aggregate(
                &commits[i],
                &proofs[i],
                &set[i],
                &value_sub_vector[i],
                n,
            )?);
        }
        if scalars.len() != pi.len() {
            return Err(ERR_X_COM_SIZE.to_owned());
        }

        let scalars_u64: Vec<&[u64; 4]> = scalars.iter().map(|s| &s.0).collect();
        let bases: Vec<VeccomG1Affine> = pi.iter().map(|s| s.proof.into_affine()).collect();
        // proof = \prod pi[i] ^ tj[i]
        let proof = VeccomG1Affine::sum_of_products(&bases[..], &scalars_u64);

        Ok(Proof {
            ciphersuite: commits[0].ciphersuite,
            proof,
        })
    }

    /// TODO: description
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
        if !check_ciphersuite(com.ciphersuite) {
            return false;
        }
        if com.ciphersuite != verifier_params.ciphersuite || com.ciphersuite != self.ciphersuite {
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

        // if the length == 1, call normal verification method
        if set.len() == 1 {
            return self.verify(&verifier_params, &com, value_sub_vector[0].as_ref(), set[0]);
        }
        // 1. compute tmp
        // 1.1 get the list of scalas, return false if this failed
        let ti = match hash_to_ti_repr(com, set, value_sub_vector, verifier_params.n) {
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

        let mut bases: Vec<VeccomG2Affine> = vec![];
        for index in set.iter().take(ti.len()) {
            bases.push(verifier_params.generators[verifier_params.n - index - 1]);
        }
        let scalars_u64: Vec<&[u64; 4]> = ti.iter().map(|s| &s.0).collect();
        let param_subset_sum = VeccomG2Affine::sum_of_products(&bases, &scalars_u64);

        // 2.3 proof ^ {-tmp}
        let mut proof_mut = self.proof;
        tmp.negate();
        proof_mut.mul_assign(tmp);

        // 3 pairing product
        Bls12::pairing_product(
            param_subset_sum,
            com_mut,
            VeccomG2Affine::one().into_projective(),
            proof_mut,
        ) == verifier_params.gt_elt
    }

    pub fn cross_commit_batch_verify<Blob: AsRef<[u8]>>(
        &self,
        verifier_params: &VerifierParams,
        com: &Vec<Commitment>,
        set: &Vec<Vec<usize>>,
        value_sub_vector: &Vec<Vec<Blob>>,
    ) -> bool {
        // TODO: check ciphersuite

        let num_commit = com.len();
        if num_commit != set.len() || num_commit != value_sub_vector.len() || num_commit == 0 {
            // length does not match
            return false;
        }
        for j in 0..num_commit {
            if set[j].len() != value_sub_vector[j].len() {
                // length does not match
                return false;
            }
        }
        if num_commit == 1 {
            // call normal batch verification
            return self.batch_verify(&verifier_params, &com[0], &set[0], &value_sub_vector[0]);
        }

        // generate all the t_i-s for j \in [num_commit]
        let mut ti_s: Vec<Vec<Fr>> = vec![];
        for i in 0..num_commit {
            let ti = match hash_to_ti_fr(&com[i], &set[i], &value_sub_vector[i], verifier_params.n)
            {
                Err(_e) => return false,
                Ok(p) => p,
            };
            ti_s.push(ti);
        }
        // generate tj
        let tj = match hash_to_tj(&com, &set, &value_sub_vector, verifier_params.n) {
            Err(_e) => return false,
            Ok(p) => p,
        };

        // we want to check
        //  \prod_{j=1}^num_commit e(com[j], g2^{\sum alpha^{n + 1 -i} * t_i,j} ) ^ t_j
        //      ?= e (proof, g2) * e (g1, g2)^{alpha^{n+1} * {\sum m_i,j * t_i,j * tj}}
        // step 1. compute tmp = \sum m_i,j * t_i,j * tj
        let mut tmp = Fr::zero();
        for j in 0..num_commit {
            let mut tmp2 = Fr::zero();

            // tmp2 = sum_i m_ij * t_ij
            for i in 0..ti_s[j].len() {
                let mut tmp3 = ti_s[j][i];
                let mij = hash_to_field_veccom(value_sub_vector[j][i].as_ref());
                tmp3.mul_assign(&mij);
                tmp2.add_assign(&tmp3);
            }
            // tmp2 = tj * tmp2
            let tmp3 = match Fr::from_repr(tj[j]) {
                Ok(p) => p,
                Err(_e) => return false,
            };
            tmp2.mul_assign(&tmp3);
            // tmp += tj * (sum_i m_ij * t_ij)
            tmp.add_assign(&tmp2);
        }

        // 1.1 if tmp == 0 (should never happen in practise)
        assert!(!tmp.is_zero());
        let tmp_inverse = tmp.inverse().unwrap();

        // now the formula becomes
        // \prod e(com[j], g2^{\sum alpha^{n + 1 - i} * t_i,j * tj/tmp} )
        //  * e(proof^{-1/tmp}, g2)
        //  ?= e(g1, g2)^{alpha^{n+1}} == verifier_params.Fq12

        // g1_vec stores the g1 components for the pairing product
        // for j \in [num_commit], store com[j]
        let mut g1_vec: Vec<VeccomG1Affine> = vec![];
        for j in 0..num_commit {
            g1_vec.push(com[j].commit.into_affine());
            // let mut tmp2 = com[j].commit;
            // let mut scalar = match Fr::from_repr(tj[j]) {
            //     Ok(p) => p,
            //     Err(_e) => return false,
            // };
            // scalar.mul_assign(&tmp_inverse);
            // tmp2.mul_assign(scalar);
            // g1_vec.push(tmp2.into_affine());
        }
        // the last element for g1_vec is proof^{-1/tmp}
        let mut tmp2 = self.proof;
        tmp2.negate();
        tmp2.mul_assign(tmp_inverse);
        g1_vec.push(tmp2.into_affine());

        // g2_vec stores the g2 components for the pairing product
        // for j \in [num_commit], g2^{\sum alpha^{n + 1 - i} * t_i,j} * tj/tmp )
        let mut g2_vec: Vec<VeccomG2Affine> = vec![];
        for j in 0..num_commit {
            let mut tmp3 = tmp_inverse.clone();
            let scalar = match Fr::from_repr(tj[j]) {
                Ok(p) => p,
                Err(_e) => return false,
            };
            tmp3.mul_assign(&scalar);

            let mut bases: Vec<VeccomG2Affine> = vec![];
            let mut scalars_u64: Vec<[u64; 4]> = vec![];
            for i in 0..ti_s[j].len() {
                bases.push(verifier_params.generators[verifier_params.n - set[j][i] - 1]);

                let mut t = ti_s[j][i].clone();
                t.mul_assign(&tmp3);
                scalars_u64.push(t.into_repr().0);
            }

            let mut scalars_u64_ref: Vec<&[u64; 4]> = vec![];
            for i in 0..ti_s[j].len() {
                scalars_u64_ref.push(&scalars_u64[i]);
            }

            let param_subset_sum = VeccomG2Affine::sum_of_products(&bases, &scalars_u64_ref);

            g2_vec.push(param_subset_sum.into_affine());
        }
        // the last element for g1_vec is g2
        g2_vec.push(VeccomG2::one().into_affine());

        // now check the pairing product ?= verifier_params.Fq12

        Bls12::pairing_multi_product(&g2_vec[..], &g1_vec[..]) == verifier_params.gt_elt
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
        let proof = VeccomG1::deserialize(reader, compressed)?;

        // finished
        Ok(Proof {
            ciphersuite: constants[0],
            proof,
        })
    }
}

/**
 * Assumes prover_params are correctly generated for n = values.len and that index<n
 */
fn prove<Blob: AsRef<[u8]>>(
    prover_params: &ProverParams,
    values: &[Blob],
    index: usize,
) -> VeccomG1 {
    let n = values.len();
    let scalars_fr_repr: Vec<FrRepr> = values
        .iter()
        .map(|s| hash_to_field_repr_veccom(&s.as_ref()))
        .collect();
    let scalars_u64: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();
    if prover_params.precomp.len() == 512 * n {
        VeccomG1Affine::sum_of_products_precomp_256(
            &prover_params.generators[n - index..2 * n - index],
            &scalars_u64,
            &prover_params.precomp[(n - index) * 256..(2 * n - index) * 256],
        )
    } else {
        VeccomG1Affine::sum_of_products(
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
    proof: &VeccomG1,
    proof_index: usize,
    changed_index: usize,
    value_before: &[u8],
    value_after: &[u8],
) -> VeccomG1 {
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

/**
 * Assumes verifier_params are correctly generated for n such that index<n
 */
fn verify(
    verifier_params: &VerifierParams,
    com: &VeccomG1,
    proof: &VeccomG1,
    value: &[u8],
    index: usize,
) -> bool {
    // verification formula: e(com, param[n-index-1]) = gt_elt ^ hash(value) * e(proof, generator_of_g2)
    // We modify the formula in order to avoid slow exponentation in the target group (which is Fq12)
    // and perform two scalar multiplication by to 1/hash(value) in G1 instead, which is considerably faster.
    // We also move the pairing from the right-hand-side to the left-hand-side in order
    // to take advantage of the pairing product computation, which is faster than two pairings.
    let hash = hash_to_field_veccom(&value);
    let hash_inverse = match hash.inverse() {
        Some(p) => p,
        // should not arrive here since hash to field will never return 0
        None => panic!("hash_to_field_veccom failed"),
    };

    let n = verifier_params.generators.len();
    let mut com_mut = *com;
    let mut proof_mut = *proof;
    proof_mut.negate();

    // The following may be a tiny bit faster -- not enough to show up on a benchmark
    /*let mut w = Wnaf::new();
    let mut wnaf = w.scalar(h_inverse.into());
    let com_mut = wnaf.base(com_mut);
    let proof_mut = wnaf.base(proof_mut);*/
    com_mut.mul_assign(hash_inverse);
    proof_mut.mul_assign(hash_inverse);
    Bls12::pairing_product(
        verifier_params.generators[n - index - 1],
        com_mut,
        VeccomG2Affine::one(),
        proof_mut,
    ) == verifier_params.gt_elt
}
