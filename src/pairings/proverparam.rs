use super::ciphersuite::*;
use super::err::*;
use super::ProverParams;
use pairing::serdes::SerDes;
use pairing::{bls12_381::*, CurveAffine};
use pairings::*;

impl ProverParams {
    /// pre-process the public parameters with precomputation value set to 3
    pub fn precomp_3(&mut self) {
        self.ciphersuite = 1;
        let twice_n = self.generators.len();
        self.precomp = vec![VeccomG1Affine::zero(); 3 * twice_n];
        for i in 0..twice_n {
            self.generators[i].precomp_3(&mut self.precomp[i * 3..(i + 1) * 3]);
        }
        self.pp_len = self.n * 6;
    }

    /// pre-process the public parameters with precomputation value set to 256
    pub fn precomp_256(&mut self) {
        self.ciphersuite = 2;
        let twice_n = self.generators.len();
        self.precomp = vec![VeccomG1Affine::zero(); 256 * twice_n];
        for i in 0..twice_n {
            self.generators[i].precomp_256(&mut self.precomp[i * 256..(i + 1) * 256]);
        }
        self.pp_len = self.n * 512;
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
        // get the system parameter, which implicitly
        // checks the ciphersuite id
        // let sp = match get_system_paramter(self.ciphersuite) {
        //     Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        //     Ok(p) => p,
        // };

        // check that #generators and #precomp matches sp value
        if self.n * 2 != self.generators.len() || self.pp_len != self.precomp.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_INVALID_VALUE,
            ));
        }

        // write csid
        writer.write_all(&[self.ciphersuite])?;
        writer.write_all(&self.n.to_le_bytes())?;
        //    let mut buf: Vec<u8> = vec![self.ciphersuite] ;

        // write the generators
        for e in self.generators.iter() {
            e.serialize(&mut writer, compressed)?;
        }
        writer.write_all(&self.pp_len.to_le_bytes())?;
        if self.pp_len != 0 {
            for e in self.precomp.iter() {
                e.serialize(&mut writer, compressed)?;
            }
        }
        // format the output
        //    writer.write_all(&buf)?;

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
        // read into buf of compressed size
        let mut csid = vec![0u8; 1];
        reader.read_exact(&mut csid)?;

        if !check_ciphersuite(csid[0]) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_CIPHERSUITE.to_owned(),
            ));
        }

        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        let n = usize::from_le_bytes(buf);
        // get the system parameter, which implicitly
        // checks the ciphersuite id
        // let sp = match get_system_paramter(csid[0]) {
        //     Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        //     Ok(p) => p,
        // };

        // write csid
        let mut generators: Vec<VeccomG1Affine> = vec![];

        // write the generators
        for _i in 0..n * 2 {
            let g = VeccomG1Affine::deserialize(reader, compressed)?;
            generators.push(g);
        }

        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        let pp_len = usize::from_le_bytes(buf);

        let mut precomp: Vec<VeccomG1Affine> = vec![];
        for _i in 0..pp_len {
            let g = VeccomG1Affine::deserialize(reader, compressed)?;
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
