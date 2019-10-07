use super::{commit, Params, HASH_LEN};

/**
 * Assumes params are properly generated, params.n == values.len() and index<params.n
 */
pub fn prove_from_scratch(params: &Params, values: &[&[u8]], index: usize) -> Vec<u8> {
    prove_rec(params, values, params.max_depth, 0, index)
}
/**
 * Assumes params and tree are properly generated and index<params.n
 */
pub fn prove_from_tree(params: &Params, hash_tree: &[u8], index: usize) -> Vec<u8> {
    let mut proof = vec![0u8; params.max_depth * HASH_LEN];
    let mut i = (1 << params.max_depth) | index;
    // node i at depth k is stored starting in location index = (2^k+i)*HASH_LEN (like a heap, except at HASH_LEN per item)
    // its sibling is at index +/- HASH_LEN; its parent is at index/2
    let mut slice_start;
    let mut slice_end = 0usize;
    while i > 1 {
        let sibling = i ^ 1;
        slice_start = slice_end;
        slice_end = slice_start + HASH_LEN;
        let tree_location = sibling * HASH_LEN;
        proof[slice_start..slice_end]
            .copy_from_slice(&hash_tree[tree_location..tree_location + HASH_LEN]);
        i /= 2;
    }
    proof
}

fn prove_rec(
    params: &Params,
    values: &[&[u8]],
    height: usize,
    current_node_index: usize,
    index_being_proven: usize,
) -> Vec<u8> {
    if height > 0 {
        // internal node
        let (next_step_index, next_sibling_index) = if (index_being_proven >> (height - 1)) & 1 == 0
        {
            // next step is to the left, so push right child onto the proof
            (current_node_index * 2, current_node_index * 2 + 1)
        } else {
            // next step is to the right, so push left child onto the proof
            (current_node_index * 2 + 1, current_node_index * 2)
        };
        let mut ret = prove_rec(
            params,
            values,
            height - 1,
            next_step_index,
            index_being_proven,
        );
        let com = commit::commit_rec(params, values, height - 1, next_sibling_index);
        let start_index = (height - 1) * HASH_LEN;
        ret[start_index..start_index + HASH_LEN].copy_from_slice(&com);
        ret
    } else {
        // leaf level, it doesn't matter what the proof is, because it will get filled in by recursive levels above
        vec![0u8; params.max_depth * HASH_LEN]
    }
}

/**
* For updating your proof when someone else's value changes
* Not for updating your own proof when your value changes -- because then the proof does not change!
* fast_proof_update_info, if supplied, speeds this up. (It is obtained from commit_update.)

* Assumes params, proof, changed_index_proof, fast_proof_update_info (unless None) and are properly generated.
* Assumes proof_index<params.n and changed_index<params.n
*/

pub fn proof_update(
    params: &Params,
    proof: &mut [u8],
    proof_index: usize,
    changed_index: usize,
    changed_index_proof: &[u8],
    value_after: &[u8],
    fast_proof_update_info: Option<&[u8]>,
) {
    if proof_index != changed_index {
        let mut path_diff = (proof_index ^ changed_index) >> 1;
        let mut update_height = 0;
        while path_diff != 0 {
            update_height += 1;
            path_diff >>= 1;
        }
        let slice_start = update_height * HASH_LEN;
        let slice_end = slice_start + HASH_LEN;
        match fast_proof_update_info {
            None => {
                proof[slice_start..slice_end].copy_from_slice(&commit::commit_update_helper(
                    params,
                    changed_index,
                    changed_index_proof,
                    value_after,
                    update_height,
                    None,
                ));
            }
            Some(h) => {
                proof[slice_start..slice_end].copy_from_slice(&h[slice_start..slice_end]);
            }
        }
    }
}
