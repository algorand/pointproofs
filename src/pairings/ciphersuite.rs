use super::SystemParam;

const VALID_CIPHERSUITE: [u8; 3] = [0u8, 1u8, 2u8];

pub type Ciphersuite = u8;

/// Checks if csid is supported. Currently only support csid = 0.
pub fn check_ciphersuite(csid: Ciphersuite) -> bool {
    VALID_CIPHERSUITE.contains(&csid)
}

pub fn get_system_paramter(csid: Ciphersuite) -> Result<SystemParam, String> {
    match csid {
        // non pre-computation
        0 => Ok(SystemParam {
            ciphersuite: csid,
            n: 32,
            pp_len: 0,
        }),
        // pre-computation with parameter 3
        // pp_len = n * 2 * 3
        1 => Ok(SystemParam {
            ciphersuite: csid,
            n: 32,
            pp_len: 192,
        }),
        // pre-computation with parameter 256
        // pp_len = n * 2 * 256
        2 => Ok(SystemParam {
            ciphersuite: csid,
            n: 32,
            pp_len: 16384,
        }),
        _ => Err(super::err::ERR_CIPHERSUITE.to_owned()),
    }
}
