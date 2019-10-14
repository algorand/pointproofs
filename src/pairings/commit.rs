use super::ciphersuite::*;
use super::err::*;
use super::{Commitment, ProverParams};
use ff::{Field, PrimeField};
use pairing::hash_to_field::HashToField;
use pairing::serdes::SerDes;
use pairing::{bls12_381::*, CurveAffine, CurveProjective};

impl Commitment {
    pub fn new<Blob: AsRef<[u8]>>(
        prover_params: &ProverParams,
        values: &[Blob],
    ) -> Result<Self, String> {
        // implicitly checks that cipersuite is supported
        let sp = get_system_paramter(prover_params.ciphersuite)?;

        if sp.n != values.len() {
            return Err(ERR_INVALID_VALUE.to_owned());
        };

        Ok(Self {
            // FIXME: there is a potential mismatch of ciphersuite
            // prover_params.ciphersuite can be 0, 1, 2
            // while that of commitment and verifier_params are all 0
            ciphersuite: 0,
            // commit: commit(&sp, &prover_params, values),
            commit: commit(&prover_params, values),
        })
    }
    // TODO: return errors?
    pub fn update<Blob: AsRef<[u8]>>(
        &mut self,
        prover_params: &ProverParams,
        changed_index: usize,
        value_before: Blob,
        value_after: Blob,
    ) {
        (*self).commit = commit_update(
            &prover_params,
            &self.commit,
            changed_index,
            value_before.as_ref(),
            value_after.as_ref(),
        )
    }
}
type Compressed = bool;
impl SerDes for Commitment {
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
        self.commit.serialize(&mut buf, compressed)?;

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

        // read into commit
        let commit = G1::deserialize(reader, compressed)?;

        // finished
        Ok(Commitment {
            ciphersuite: constants[0],
            commit,
        })
    }
}

/**
 * Assumes prover_params are correctly generated for n = values.len
 */
fn commit<Blob: AsRef<[u8]>>(
    //    sp: &SystemParam,
    prover_params: &ProverParams,
    values: &[Blob],
) -> G1 {
    // TODO: hashing is now a noticeable portion of commit time. Need rethink hashing.
    let n = values.len();

    let scalars_fr_repr: Vec<FrRepr> = values
        .iter()
        .map(|s| {
            HashToField::<Fr>::new(s.as_ref(), None)
                .with_ctr(0)
                .into_repr()
        })
        .collect();
    let scalars_u64: Vec<&[u64; 4]> = scalars_fr_repr.iter().map(|s| &s.0).collect();
    if prover_params.precomp.len() == 512 * n {
        G1Affine::sum_of_products_precomp_256(
            &prover_params.generators[0..n],
            &scalars_u64,
            &prover_params.precomp,
        )
    } else {
        G1Affine::sum_of_products(&prover_params.generators[0..n], &scalars_u64)
    }
}

/**
 * Assumes prover_params are correctly generated for n such that changed_index<n
 */
fn commit_update(
    prover_params: &ProverParams,
    com: &G1,
    changed_index: usize,
    value_before: &[u8],
    value_after: &[u8],
) -> G1 {
    let mut multiplier = HashToField::<Fr>::new(&value_before, None).with_ctr(0);
    multiplier.negate();
    multiplier.add_assign(&HashToField::<Fr>::new(&value_after, None).with_ctr(0));

    let res = if prover_params.precomp.len() == 3 * prover_params.generators.len() {
        prover_params.generators[changed_index].mul_precomp_3(
            multiplier,
            &prover_params.precomp[changed_index * 3..(changed_index + 1) * 3],
        )
    } else if prover_params.precomp.len() == 256 * prover_params.generators.len() {
        prover_params.generators[changed_index].mul_precomp_256(
            multiplier,
            &prover_params.precomp[changed_index * 256..(changed_index + 1) * 256],
        )
    } else {
        prover_params.generators[changed_index].mul(multiplier)
    };

    let mut new_com = *com;
    new_com.add_assign(&res);
    new_com
}
//
// /**
//  * convert a commitment (which is a projective G1 element) into a string of 48 bytes
//  * Copied from the bls library
//  */
// fn convert_commitment_to_bytes(commitment: &G1) -> [u8; 48] {
//     let s = pairing::bls12_381::G1Compressed::from_affine(commitment.into_affine());
//     let mut out: [u8; 48] = [0; 48];
//     out.copy_from_slice(s.as_ref());
//     out
// }
//
// /**
//  * Take an array of 48 bytes and output a commitment
//  * Copied from the bls library
//  * In case bytes don't convert to a meaningful element of G1, defaults to the group generator
//  */
// fn convert_bytes_to_commitment(input: &[u8; 48]) -> G1 {
//     let mut commitment_compressed = G1Compressed::empty();
//     commitment_compressed.as_mut().copy_from_slice(input);
//     match commitment_compressed.into_affine() {
//         Ok(commitment_affine) => commitment_affine.into_projective(),
//         Err(_) => G1::zero(),
//     }
// }

#[cfg(test)]
/**
 * Updates the commitment to commit to a value whose hash is 0 in changed_index
 * Needed for testing only (in order to test verify, which handles the case of hash ==  0 separately)
 * Assumes prover_params are correctly generated for n such that changed_index<n
 */
pub fn update_to_zero_hash(
    prover_params: &ProverParams,
    com: &Commitment,
    changed_index: usize,
    value_before: &[u8],
) -> Commitment {
    let mut multiplier = HashToField::<Fr>::new(&value_before, None).with_ctr(0);
    multiplier.negate();

    let res = if prover_params.precomp.len() == 3 * prover_params.generators.len() {
        prover_params.generators[changed_index].mul_precomp_3(
            multiplier,
            &prover_params.precomp[changed_index * 3..(changed_index + 1) * 3],
        )
    } else if prover_params.precomp.len() == 256 * prover_params.generators.len() {
        prover_params.generators[changed_index].mul_precomp_256(
            multiplier,
            &prover_params.precomp[changed_index * 256..(changed_index + 1) * 256],
        )
    } else {
        prover_params.generators[changed_index].mul(multiplier)
    };

    let mut new_com = com.clone();
    new_com.commit.add_assign(&res);
    new_com
}
