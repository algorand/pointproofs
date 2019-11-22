use super::ciphersuite::*;
use super::err::*;
use super::VerifierParams;
use pairing::bls12_381::*;
use pairing::serdes::SerDes;
use pairings::*;

type Compressed = bool;

impl SerDes for VerifierParams {
    /// Convert a ProverParam into a blob:
    ///
    /// `|ciphersuite id | n | generators | gt_element` => bytes
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

        // check that #generators matches sp
        if self.n != self.generators.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_INVALID_VALUE,
            ));
        }

        writer.write_all(&[self.ciphersuite])?;
        writer.write_all(&self.n.to_le_bytes())?;

        // write csid
        //        let mut buf: Vec<u8> = vec![self.ciphersuite];

        // write the generators
        for e in self.generators.iter() {
            e.serialize(&mut writer, compressed)?;
        }

        self.gt_elt.serialize(&mut writer, compressed)?;

        // format the output
        //    writer.write_all(&buf)?;

        Ok(())
    }
    /// Convert a blob into a ProverParam:
    ///
    /// bytes => `|ciphersuite id | n | generators | gt_element`
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

        // write the generators
        let mut generators: Vec<VeccomG2Affine> = vec![];
        for _i in 0..n {
            let g = VeccomG2Affine::deserialize(reader, compressed)?;
            generators.push(g);
        }
        let gt_elt = Fq12::deserialize(reader, compressed)?;

        // format the output
        Ok(Self {
            ciphersuite: csid[0],
            n,
            generators,
            gt_elt,
        })
    }
}

impl std::cmp::PartialEq for VerifierParams {
    /// Convenient function to compare secret key objects
    fn eq(&self, other: &Self) -> bool {
        self.ciphersuite == other.ciphersuite
            && self.n == other.n
            && self.generators == other.generators
            && self.gt_elt == other.gt_elt
    }
}
