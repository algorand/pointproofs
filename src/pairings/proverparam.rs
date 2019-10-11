use super::ciphersuite::*;
use super::err::*;
use super::{ProverParams, SystemParam, VerifierParams};
use ff::Field;
use pairing::hash_to_field::HashToField;
use pairing::serdes::SerDes;
use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};

impl ProverParams {
    /// pre-process the public parameters with precomputation value set to 3
    pub fn precomp_3(&mut self) {
        self.ciphersuite = 1;
        let twice_n = self.generators.len();
        self.precomp = vec![G1Affine::zero(); 3 * twice_n];
        for i in 0..twice_n {
            self.generators[i].precomp_3(&mut self.precomp[i * 3..(i + 1) * 3]);
        }
    }

    /// pre-process the public parameters with precomputation value set to 256
    pub fn precomp_256(&mut self) {
        self.ciphersuite = 2;
        let twice_n = self.generators.len();
        self.precomp = vec![G1Affine::zero(); 256 * twice_n];
        for i in 0..twice_n {
            self.generators[i].precomp_256(&mut self.precomp[i * 256..(i + 1) * 256]);
        }
    }
}

type Compressed = bool;

impl SerDes for ProverParams {
    /// Convert a ProverParam into a blob:
    ///
    /// `|ciphersuite id | generators | [pre_compute]` => bytes
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        compressed: Compressed,
    ) -> std::io::Result<()> {
        // get the system parameter, which implicitly
        // checks the ciphersuite id

        let sp = match get_system_paramter(self.ciphersuite) {
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Ok(p) => p,
        };

        // write csid
        let mut buf: Vec<u8> = vec![self.ciphersuite];

        // write the generators
        for e in self.generators.iter() {
            e.serialize(&mut buf, compressed)?;
        }
        println!("{} {}", self.generators.len(), sp.n * 2);

        if sp.pp_len != 0 {
            for e in self.precomp.iter() {
                e.serialize(&mut buf, compressed)?;
            }

            println!("{} {}", self.precomp.len(), sp.pp_len);
        }
        //    println!("{:?}", buf.len());
        // format the output
        writer.write_all(&buf)?;

        Ok(())
    }

    /// Convert a blob into a ProverParam:
    ///
    /// bytes => `|ciphersuite id | generators | [pre_compute]`
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        compressed: Compressed,
    ) -> std::io::Result<Self> {
        // read into buf of compressed size
        let mut csid = vec![0u8; 1];
        reader.read_exact(&mut csid)?;

        // get the system parameter, which implicitly
        // checks the ciphersuite id
        let sp = match get_system_paramter(csid[0]) {
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Ok(p) => p,
        };

        // write csid
        let mut generators: Vec<G1Affine> = vec![];

        // write the generators
        for i in 0..sp.n * 2 {
            let g = G1Affine::deserialize(reader, compressed)?;
            generators.push(g);
        }

        let mut precomp: Vec<G1Affine> = vec![];
        for i in 0..sp.pp_len {
            let g = G1Affine::deserialize(reader, compressed)?;
            precomp.push(g);
        }

        // format the output
        Ok(Self {
            ciphersuite: csid[0],
            generators,
            precomp,
        })
    }
}

impl std::cmp::PartialEq for ProverParams {
    /// Convenient function to compare secret key objects
    fn eq(&self, other: &Self) -> bool {
        self.ciphersuite == other.ciphersuite
            && self.generators == other.generators
            && self.precomp == other.precomp
    }
}
