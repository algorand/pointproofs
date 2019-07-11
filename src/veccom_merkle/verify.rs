use super::{Params,commit};



pub fn verify(params : &Params, com : &[u8], proof : &[u8], value : &[u8], index : usize) -> bool {
    // TODO: is this the right way to compare old and new commitments?
    // First converting Vec to slice and then doing the comparison seems a bit strange.
    let new_com : &[u8] = &commit::commit_update_helper(params, index, proof, value, params.max_depth, None);
    com == new_com
}
  