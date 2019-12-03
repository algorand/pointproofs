const VALID_CIPHERSUITE: [u8; 1] = [0u8];

pub type Ciphersuite = u8;

/// Checks if csid is supported. Currently only support csid = 0.
pub fn check_ciphersuite(csid: Ciphersuite) -> bool {
    VALID_CIPHERSUITE.contains(&csid)
}
