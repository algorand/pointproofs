use super::{Params,HASH_LEN};
use sha2::Digest;

/**
 * Assumes params are properly generated and params.n == values.len()
 */
pub fn commit_no_tree(params: &Params, values: &[&[u8]]) -> Vec<u8> {
    commit_rec(params, values, params.max_depth, 0)
}

/**
 * Assumes params are properly generated and params.n == values.len(). 
 * The commitment will be in the returned vector slice [HASH_LEN..2*HASH_LEN]
 */
pub fn commit_with_tree(params: &Params, values: &[&[u8]]) -> Vec<u8> {
    // node i at depth k is stored starting in location (2^k+i)*HASH_LEN (like a heap, except at HASH_LEN per item)
    let mut num_nodes_above = 1<<params.max_depth; // number of nodes above the current level, plus 1 (where current level starts at the leaves)
    let num_leaves = ((params.n+1)/2)*2; // round up n to the nearest even number
    let mut hash_tree = vec!(0u8; (num_nodes_above+num_leaves)*HASH_LEN);

    for i in 0 .. params.n {
        let prefix : [u8; 1] = [0u8];
        let mut hasher = sha2::Sha256::new(); 
        hasher.input(&prefix);
        hasher.input(&params.n_bytes);
        hasher.input(&values[i]);
        let tree_location = (num_nodes_above+i)*HASH_LEN;
        hash_tree[tree_location..tree_location+HASH_LEN].copy_from_slice(&hasher.result());
    }

    let mut num_occupied = num_leaves;
    let double_hash_len = 2*HASH_LEN;
    for _height in 1..params.max_depth+1 {
        num_occupied = (num_occupied+1)/2; // number of nonzero entries in the current level, computed by dividing previous level by 2 with rounding up
        num_nodes_above /= 2; 

        for i in num_nodes_above..num_nodes_above+num_occupied {
            let prefix : [u8; 1] = [1u8];
            let mut hasher = sha2::Sha256::new();
            hasher.input(&prefix);
            hasher.input(&params.n_bytes);
            let tree_location = i*HASH_LEN;
            let children_start = 2*tree_location;
            hasher.input(&hash_tree[children_start..children_start+double_hash_len]);
            hash_tree[tree_location..tree_location+HASH_LEN].copy_from_slice(&hasher.result());
        }
    }
    hash_tree
}


// TODO: maybe the output type should be GenericArray rather than Vec. 
pub fn commit_rec(params: &Params, values: &[&[u8]], height: usize, index: usize) -> Vec<u8> {
    // We number levels from 0 at the root to params.max_depth at the leaves
    // We number nodes at each level from 0 to 2^level - 1
    // height = params.max_depth - level -- i.e., 0 at the leaves, params.max_depth at the root
    // Any node that is not an ancestor of a leaf numbered less than n has value 0 (that is, [0u8; HASH_LEN])
    let num_occupied = (params.n+(1<<height)-1)>>height; // divide params.itn by 2^height with rouding up to get number of occupied tree cells in this level
    let ret = if index < num_occupied { // this node has a descendent leaf numbered less than n
        let mut hasher = sha2::Sha256::new(); 
        if height == 0 { // leaf node
            let prefix : [u8; 1] = [0u8];
            hasher.input(&prefix);
            hasher.input(&params.n_bytes);
            hasher.input(&values[index]);
        }
        else { // internal node
            let prefix : [u8; 1] = [1u8];
            hasher.input(&prefix);
            hasher.input(&params.n_bytes);
            hasher.input(&commit_rec(params, values, height-1, index*2));
            hasher.input(&commit_rec(params, values, height-1, index*2+1));
        }
        hasher.result().to_vec()
    }
    else { // this node has no descendent leaves numbered less than n
        vec![0u8; HASH_LEN]
    };
    ret
}



/**
 * Assumes changed_index<params.n, and params and changed_index_proof were properly generated.
 */
pub fn commit_update(params: &Params, changed_index : usize, changed_index_proof : &[u8], value_after : &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut fast_proof_update_info = vec!(0u8; params.max_depth*HASH_LEN);
    let res = commit_update_helper(params, changed_index, changed_index_proof, value_after, params.max_depth, Some(&mut fast_proof_update_info));
    (res, fast_proof_update_info)
}

// TODO: maybe the output type should be GenericArray rather than Vec. 
pub fn commit_update_helper(params: &Params, changed_index : usize, changed_index_proof : &[u8], value_after : &[u8], update_height : usize, mut fast_proof_update_info : Option<& mut [u8]>) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    let prefix : [u8; 1] = [0u8];
    hasher.input(&prefix);
    hasher.input(&params.n_bytes);
    hasher.input(value_after);
    let mut new_com = hasher.result(); 

    match fast_proof_update_info {
        None => (),
        Some(ref mut g) => g[0*HASH_LEN..HASH_LEN].copy_from_slice(&new_com)
    };

    let mut child_index = changed_index;

    for i in 0..update_height {
        let mut hasher = sha2::Sha256::new();
        let prefix : [u8; 1] = [1u8];
        hasher.input(&prefix);
        hasher.input(&params.n_bytes);
        if child_index & 1 == 0 { // the left child is on the path to the changed value
            hasher.input(new_com);
            hasher.input(&changed_index_proof[i*HASH_LEN..(i+1)*HASH_LEN]);
        }
        else {
            hasher.input(&changed_index_proof[i*HASH_LEN..(i+1)*HASH_LEN]);
            hasher.input(new_com);
        }
        child_index >>= 1;
        new_com = hasher.result();
        if i<params.max_depth-1 {
            match fast_proof_update_info {
                None => (),
                Some(ref mut g) => g[(i+1)*HASH_LEN..(i+2)*HASH_LEN].copy_from_slice(&new_com)
            };
        }

    }
    new_com.to_vec() 
}

/**
 * Assumes changed_index<params.n, and params and tree were properly generated.
 */
pub fn tree_update(params: &Params, changed_index : usize, value_after : &[u8], tree : &mut [u8]) {
    let mut hasher = sha2::Sha256::new();
    let prefix : [u8; 1] = [0u8];
    hasher.input(&prefix);
    hasher.input(&params.n_bytes);
    hasher.input(value_after);

    let mut ancestor_index = (1<<params.max_depth) | changed_index;

    let tree_index = ancestor_index*HASH_LEN;
    tree[tree_index..tree_index+HASH_LEN].copy_from_slice(&hasher.result());

    let double_hash_len = 2*HASH_LEN;
    while ancestor_index>1 {
        let mut hasher = sha2::Sha256::new();
        ancestor_index /= 2;
        let prefix : [u8; 1] = [1u8];
        hasher.input(&prefix);
        hasher.input(&params.n_bytes);
        let tree_location = ancestor_index * HASH_LEN;
        let children_start = 2*tree_location;
        hasher.input(&tree[children_start..children_start+double_hash_len]);
        tree[tree_location..tree_location+HASH_LEN].copy_from_slice(&hasher.result());
    }
}
