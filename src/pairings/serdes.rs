//! this file is part of the pointproofs.
//! It defines APIs for (de)serialization.

use pairing::bls12_381::*;
use pairing::serdes::SerDes;
use pairing::CurveProjective;
use pairings::err::*;
use pairings::param::*;
use pairings::pointproofs_groups::*;
use pairings::*;

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

        // compressed must be true
        if !compressed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_COMPRESS,
            ));
        }

        let mut buf: Vec<u8> = vec![self.ciphersuite];
        self.commit.into_affine().serialize(&mut buf, compressed)?;

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
        // compressed must be true
        if !compressed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_COMPRESS,
            ));
        }
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
        let commit = PointproofsG1::deserialize(reader, compressed)?;

        // finished
        Ok(Commitment {
            ciphersuite: constants[0],
            commit,
        })
    }
}

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
        // compressed must be true
        if !compressed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_COMPRESS,
            ));
        }
        // check the cipher suite id
        if !check_ciphersuite(self.ciphersuite) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_CIPHERSUITE,
            ));
        }
        let mut buf: Vec<u8> = vec![self.ciphersuite];
        self.proof.into_affine().serialize(&mut buf, compressed)?;

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
        // compressed must be true
        if !compressed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_COMPRESS,
            ));
        }
        // constants stores ciphersuite id
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
        let proof = PointproofsG1::deserialize(reader, compressed)?;

        // finished
        Ok(Proof {
            ciphersuite: constants[0],
            proof,
        })
    }
}

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
        // check the cipher suite id
        if !check_ciphersuite(self.ciphersuite) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_CIPHERSUITE,
            ));
        }
        if !compressed {
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

        if self.n > (u32::max_value() as usize) || self.pp_len > (u32::max_value() as usize) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_INVALID_VALUE,
            ));
        }

        // write csid
        writer.write_all(&[self.ciphersuite])?;
        writer.write_all(&(self.n as u32).to_le_bytes())?;

        // write the generators
        for e in self.generators.iter() {
            e.serialize(&mut writer, true)?;
        }
        writer.write_all(&(self.pp_len as u32).to_le_bytes())?;
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
        if !compressed {
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
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let n = u32::from_le_bytes(buf) as usize;
        if n > 65536 || n == 0 {
            // set an upper bounded of n
            // to prevent potential DoS kind of attacks
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_MAX_N,
            ));
        }

        // write csid
        let mut generators: Vec<PointproofsG1Affine> = vec![];

        // write the generators
        for _i in 0..n * 2 {
            let g = PointproofsG1Affine::deserialize(reader, true)?;
            generators.push(g);
        }

        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let pp_len = u32::from_le_bytes(buf) as usize;

        let mut precomp: Vec<PointproofsG1Affine> = vec![];
        for _i in 0..pp_len {
            let g = PointproofsG1Affine::deserialize(reader, true)?;
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

impl SerDes for VerifierParams {
    /// Convert a VerifierParams into a blob:
    ///
    /// `|ciphersuite id | n | generators | pp_len | pre_comp | gt_element` => bytes
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn serialize<W: std::io::Write>(
        &self,
        mut writer: &mut W,
        compressed: Compressed,
    ) -> std::io::Result<()> {
        // check the cipher suite id
        if !check_ciphersuite(self.ciphersuite) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_CIPHERSUITE,
            ));
        }
        if !compressed {
            // we only support compress == true mode
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_COMPRESS,
            ));
        }
        // check that #generators matches sp
        if self.n != self.generators.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_INVALID_VALUE,
            ));
        }
        if self.n > (u32::max_value() as usize) || self.pp_len > (u32::max_value() as usize) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_INVALID_VALUE,
            ));
        }

        writer.write_all(&[self.ciphersuite])?;
        writer.write_all(&(self.n as u32).to_le_bytes())?;

        // write the generators
        for e in self.generators.iter() {
            e.serialize(&mut writer, true)?;
        }

        writer.write_all(&(self.pp_len as u32).to_le_bytes())?;
        if self.pp_len != 0 {
            for e in self.precomp.iter() {
                e.serialize(&mut writer, true)?;
            }
        }

        self.gt_elt.serialize(&mut writer, true)?;

        Ok(())
    }
    /// Convert a blob into a VerifierParams:
    ///
    /// bytes => `|ciphersuite id | n | generators | pp_len | pre_comp | gt_element`
    ///
    /// Returns an error if ciphersuite id is invalid or serialization fails.
    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        compressed: Compressed,
    ) -> std::io::Result<Self> {
        if !compressed {
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
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let n = u32::from_le_bytes(buf) as usize;
        if n > 65536 || n == 0 {
            // set an upper bounded of n
            // to prevent potential DoS kind of attacks
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ERR_MAX_N,
            ));
        }

        // write the generators
        let mut generators: Vec<PointproofsG2Affine> = vec![];
        for _i in 0..n {
            let g = PointproofsG2Affine::deserialize(reader, true)?;
            generators.push(g);
        }

        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let pp_len = u32::from_le_bytes(buf) as usize;

        let mut precomp: Vec<PointproofsG1Affine> = vec![];
        for _i in 0..pp_len {
            let g = PointproofsG1Affine::deserialize(reader, true)?;
            precomp.push(g);
        }

        let gt_elt = Fq12::deserialize(reader, true)?;

        // format the output
        Ok(Self {
            ciphersuite: csid[0],
            n,
            generators,
            pp_len: 0,
            precomp: vec![],
            gt_elt,
        })
    }
}
