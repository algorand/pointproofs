use super::{Params, commit};


pub fn prove_from_scratch(params: &Params, values: &[&[u8]], index : usize) -> Vec<u8> {
    // TODO: error handling if the prover params length is not equal to values length
    // TODO: figure out if the input for values is the right one to use
    // TODO: is this the correct output type?
    prove_rec(params, values, params.max_depth, 0, index)
}

pub fn prove_from_tree(params: &Params, hash_tree: &[u8], index : usize) -> Vec<u8> {
    // TODO: error handling if the prover params length is not equal to values length
    // TODO: figure out if the input for values is the right one to use
    // TODO: is this the correct output type?
    let mut proof = vec![0u8; params.max_depth*params.hash_len];
    let mut i = (1<<params.max_depth) | index;
    // node i at depth k is stored starting in location index = (2^k+i)*hash_len (like a heap, except at hash_len per item)
    // its sibling is at index +/- hash_len; its parent is at index/2
    let mut slice_start;
    let mut slice_end = 0usize;
    while i>1 {
        let sibling = i^1;
        slice_start = slice_end;
        slice_end = slice_start+params.hash_len;
        let tree_location = sibling*params.hash_len;
        proof[slice_start .. slice_end].copy_from_slice(&hash_tree[tree_location..tree_location+params.hash_len]);
        i/=2;
    }
    proof
}

fn prove_rec(params: &Params, values: &[&[u8]], height: usize, current_node_index: usize, index_being_proven: usize) -> Vec<u8> {
    if height>0{ // internal node
        let (next_step_index, next_sibling_index) = if (index_being_proven >> (height-1))&1 == 0 { // next step is to the left, so push right child onto the proof
            (current_node_index*2, current_node_index*2+1)
        } else { // next step is to the right, so push left child onto the proof
            (current_node_index*2+1, current_node_index*2)
        };
        let mut ret = prove_rec(params, values, height-1, next_step_index, index_being_proven);
        let com = commit::commit_rec(params, values, height-1, next_sibling_index);
        let start_index = (height-1)*params.hash_len;
        ret[start_index .. start_index+params.hash_len].copy_from_slice(&com);
        ret

    } else { // leaf level, so empty proof
        vec![0u8; params.max_depth*params.hash_len]
        //Vec::with_capacity(params.max_depth*params.hash_len)
    }
}
  


// For updating your proof when someone else's value changes
// Not for updating your own proof when your value changes -- because then the proof does not change!
// proof_update_helper, if supplied, speeds this up. (It is obtained from commit_update.)
// TODO: make sure the indices are within bounds? 
pub fn proof_update(params: &Params, proof : & mut [u8], proof_index : usize, changed_index : usize, changed_index_proof : &[u8], value_after : &[u8], fast_proof_update_info : Option<&[u8]>) {
    if proof_index != changed_index {
        let mut path_diff = (proof_index ^ changed_index)>>1;
        let mut update_height = 0;
        while path_diff!=0 {
            update_height+=1;
            path_diff >>= 1;
        }
        let slice_start = update_height*params.hash_len;
        let slice_end = slice_start+params.hash_len;
        match fast_proof_update_info {
            None => {
                proof[slice_start .. slice_end].
                    copy_from_slice(&commit::commit_update_helper(params, changed_index, changed_index_proof, value_after, update_height, None));
            }
            Some(h) => {
                proof[slice_start .. slice_end].
                    copy_from_slice(&h[slice_start .. slice_end]);
            }
        }
    }
}

