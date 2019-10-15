use super::ciphersuite::*;
use super::err::*;
use super::VerifierParams;
use pairing::bls12_381::*;
use pairing::serdes::SerDes;

type Compressed = bool;

impl SerDes for VerifierParams {
    /// Convert a ProverParam into a blob:
    ///
    /// `|ciphersuite id | generators | gt_element` => bytes
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

        // check that #generators matches sp
        if sp.n != self.generators.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_INVALID_VALUE,
            ));
        }

        // write csid
        let mut buf: Vec<u8> = vec![self.ciphersuite];

        // write the generators
        for e in self.generators.iter() {
            e.serialize(&mut buf, compressed)?;
        }

        self.gt_elt.serialize(&mut buf, compressed)?;

        // format the output
        writer.write_all(&buf)?;

        Ok(())
    }
    /// Convert a blob into a ProverParam:
    ///
    /// bytes => `|ciphersuite id | generators | gt_element`
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

        // write the generators
        let mut generators: Vec<G2Affine> = vec![];
        for _i in 0..sp.n {
            let g = G2Affine::deserialize(reader, compressed)?;
            generators.push(g);
        }
        let gt_elt = Fq12::deserialize(reader, compressed)?;

        // format the output
        Ok(Self {
            ciphersuite: csid[0],
            generators,
            gt_elt,
        })
    }
}

impl std::cmp::PartialEq for VerifierParams {
    /// Convenient function to compare secret key objects
    fn eq(&self, other: &Self) -> bool {
        self.ciphersuite == other.ciphersuite
            && self.generators == other.generators
            && self.gt_elt == other.gt_elt
    }
}
