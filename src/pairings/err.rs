//! this file is part of the pointproofs.
//! It defines a list of error messages.

pub(crate) const ERR_SEED_TOO_SHORT: &str = "The seed length is too short";
pub(crate) const ERR_CIPHERSUITE: &str = "Invalid ciphersuite ID";
pub(crate) const ERR_COMPRESS: &str = "Only support compress=true mode";
pub(crate) const ERR_INVALID_VALUE: &str = "Invalid number of values";
pub(crate) const ERR_INVALID_INDEX: &str = "Invalid index";
pub(crate) const ERR_DUPLICATED_INDEX: &str = "Duplicated index";
pub(crate) const ERR_INDEX_PROOF_NOT_MATCH: &str = "Length of index and proof sets do not match";
pub(crate) const ERR_X_COM_SIZE: &str =
    "Invalid sizes for commit, proof, or values for cross commit";
pub(crate) const ERR_MAX_N: &str = "N is too large";
pub(crate) const ERR_PARAM: &str = "The input parameter is not correct";
pub(crate) const ERR_INDEX_VALUE_NOT_MATCH: &str = "Length of index and value sets do not match";
