use super::{commit, Params};

/**
 * Assumes params are correctly generated and index<params.n
 */
pub fn verify(params: &Params, com: &[u8], proof: &[u8], value: &[u8], index: usize) -> bool {
    let new_com: &[u8] =
        &commit::commit_update_helper(params, index, proof, value, params.max_depth, None);
    com == new_com
}
