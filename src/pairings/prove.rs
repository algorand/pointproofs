use super::ciphersuite::*;
use super::err::*;
use super::{Commitment, Proof, ProverParams, VerifierParams};
use ff::{Field, PrimeField};
use pairing::hash_to_field::HashToField;
use pairing::serdes::SerDes;
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
        let sp = get_system_paramter(prover_params.ciphersuite)?;
        // check index is valid
        if index >= sp.n {
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
        let sp = get_system_paramter(self.ciphersuite)?;

        // check indices are valid
        if proof_index >= sp.n || changed_index >= sp.n {
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
        let sp = match get_system_paramter(self.ciphersuite) {
            Err(e) => {
                println!("{}", e);
                return false;
            }
            Ok(p) => p,
        };
        if index >= sp.n {
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

/**
 * Assumes prover_params are correctly generated for n = values.len and that index<n
 */
fn prove<Blob: AsRef<[u8]>>(prover_params: &ProverParams, values: &[Blob], index: usize) -> G1 {
    let n = values.len();
    let scalars_fr_repr: Vec<FrRepr> = values
        .iter()
        .map(|s| {
            HashToField::<Fr>::new(&s.as_ref(), None)
                .with_ctr(0)
                .into_repr()
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

        let mut multiplier = HashToField::<Fr>::new(&value_before, None).with_ctr(0);
        multiplier.negate();
        multiplier.add_assign(&HashToField::<Fr>::new(&value_after, None).with_ctr(0));

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
