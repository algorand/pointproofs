use super::ciphersuite::*;
use super::err::*;
use super::ProverParams;
use pairing::serdes::SerDes;
use pairing::{bls12_381::*, CurveAffine, CurveProjective, Engine};
use pairings::*;

impl ProverParams {
    /// pre-process the public parameters with precomputation value set to 3
    pub fn precomp_3(&mut self) {
        let twice_n = self.generators.len();
        self.precomp = vec![VeccomG1Affine::zero(); 3 * twice_n];
        for i in 0..twice_n {
            self.generators[i].precomp_3(&mut self.precomp[i * 3..(i + 1) * 3]);
        }
        self.pp_len = self.n * 6;
    }

    /// pre-process the public parameters with precomputation value set to 256
    pub fn precomp_256(&mut self) {
        let twice_n = self.generators.len();
        self.precomp = vec![VeccomG1Affine::zero(); 256 * twice_n];
        for i in 0..twice_n {
            self.generators[i].precomp_256(&mut self.precomp[i * 256..(i + 1) * 256]);
        }
        self.pp_len = self.n * 512;
    }

    /// check if the parameters are correct
    pub fn check_parameters(&self, vp: &VerifierParams) -> bool {
        if self.n != vp.n || self.ciphersuite != vp.ciphersuite {
            return false;
        }

        // prover_params.generators[i] should contain the generator of the G1 group raised to the power alpha^{i+1},
        // except prover_params.generators[n] will contain nothing useful.
        // verifier_params.generators[j] should contain the generator of the G2 group raised to the power alpha^{j+1}.
        // gt should contain the generator of the target group raised to the power alpha^{n+1}.

        let mut dh_values = Vec::with_capacity(3 * self.n);
        // If all is correct, then
        // dh_values[i] will contains the generator of the target group raised to the power alpha^{i+1}
        // We will test all possible pairing of the two arrays with each other and with the generators
        // of the two groups, and see if they all match as appropriate.

        for i in 0..self.n {
            dh_values.push(Bls12::pairing(VeccomG2::one(), self.generators[i]));
        }
        dh_values.push(vp.gt_elt);
        for i in self.n + 1..2 * self.n {
            dh_values.push(Bls12::pairing(VeccomG2::one(), self.generators[i]));
        }
        for i in 0..self.n {
            dh_values.push(Bls12::pairing(
                vp.generators[i],
                self.generators[2 * self.n - 1],
            ));
        }

        for (i, e) in dh_values.iter().enumerate().take(self.n) {
            if e != &Bls12::pairing(vp.generators[i], VeccomG1::one()) {
                return false;
            };
        }

        for i in 0..2 * self.n {
            if i != self.n {
                for j in 0..self.n {
                    if dh_values[i + j + 1] != Bls12::pairing(vp.generators[j], self.generators[i])
                    {
                        return false;
                    };
                }
            }
        }
        true
    }
}

type Compressed = bool;

impl SerDes for ProverParams {
    /// Convert a ProverParam into a blob:
    ///
    /// `|ciphersuite id | n | generators | pp_len | [pre_compute]` => bytes
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn serialize<W: std::io::Write>(
        &self,
        mut writer: &mut W,
        compressed: Compressed,
    ) -> std::io::Result<()> {
        if compressed == false {
            // we only support compress == true mode
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_COMPRESS,
            ));
        }
        // check that #generators and #precomp matches sp value
        if self.n * 2 != self.generators.len() || self.pp_len != self.precomp.len() || self.n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_INVALID_VALUE,
            ));
        }

        // write csid
        writer.write_all(&[self.ciphersuite])?;
        writer.write_all(&self.n.to_le_bytes())?;

        // write the generators
        for e in self.generators.iter() {
            e.serialize(&mut writer, true)?;
        }
        writer.write_all(&self.pp_len.to_le_bytes())?;
        if self.pp_len != 0 {
            for e in self.precomp.iter() {
                e.serialize(&mut writer, true)?;
            }
        }

        Ok(())
    }

    /// Convert a blob into a ProverParam:
    ///
    /// bytes => `|ciphersuite id | n | generators | pp_len | [pre_compute]`
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        compressed: Compressed,
    ) -> std::io::Result<Self> {
        if compressed == false {
            // we only support compress == true mode
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_COMPRESS,
            ));
        }
        // read into buf of compressed size
        let mut csid = vec![0u8; 1];
        reader.read_exact(&mut csid)?;

        if !check_ciphersuite(csid[0]) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_CIPHERSUITE.to_owned(),
            ));
        }

        // read n
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        let n = usize::from_le_bytes(buf);
        if n > 655365 && n == 0 {
            // set an upper bounded of n
            // to prevent potential DoS kind of attacks
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_MAX_N,
            ));
        }

        // write csid
        let mut generators: Vec<VeccomG1Affine> = vec![];

        // write the generators
        for _i in 0..n * 2 {
            let g = VeccomG1Affine::deserialize(reader, true)?;
            generators.push(g);
        }

        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        let pp_len = usize::from_le_bytes(buf);

        let mut precomp: Vec<VeccomG1Affine> = vec![];
        for _i in 0..pp_len {
            let g = VeccomG1Affine::deserialize(reader, true)?;
            precomp.push(g);
        }

        // format the output
        Ok(Self {
            ciphersuite: csid[0],
            n,
            generators,
            pp_len,
            precomp,
        })
    }
}

impl std::cmp::PartialEq for ProverParams {
    /// Convenient function to compare secret key objects
    fn eq(&self, other: &Self) -> bool {
        self.ciphersuite == other.ciphersuite
            && self.n == other.n
            && self.generators == other.generators
            && self.pp_len == other.pp_len
            && self.precomp == other.precomp
    }
}
