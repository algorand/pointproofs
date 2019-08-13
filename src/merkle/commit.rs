use super::Params;
use sha2::Digest;

pub fn commit_no_tree(params: &Params, values: &[&[u8]]) -> Vec<u8> {
    // TODO: error handling if the prover params.n is not equal to values length?
    commit_rec(params, values, params.max_depth, 0)
}

// TODO: error handling if the prover params.n is not equal to values length
pub fn commit_with_tree(params: &Params, values: &[&[u8]]) -> Vec<u8> {
    // node i at depth k is stored starting in location (2^k+i)*hash_len (like a heap, except at hash_len per item)
    let mut num_nodes_above = 1<<params.max_depth; // number of nodes above the current level, plus 1 (where current level starts at the leaves)
    let num_leaves = ((params.n+1)/2)*2; // round up n to the nearest even number
    // TODO: initialize to 0s or only put 0s where we don't put other values or initialize the whole thing to 0?
    let mut hash_tree = vec!(0u8; (num_nodes_above+num_leaves)*params.hash_len);
    let mut hasher = sha2::Sha256::new();

    for i in 0 .. params.n {
        let prefix : [u8; 1] = [0u8];
        hasher.input(&prefix);
        hasher.input(&params.n_bytes);
        hasher.input(&values[i]);
        let tree_location = (num_nodes_above+i)*params.hash_len;
        hash_tree[tree_location..tree_location+params.hash_len].copy_from_slice(&hasher.result_reset());
    }

    let mut num_occupied = num_leaves;
    let double_hash_len = 2*params.hash_len;
    for _height in 1..params.max_depth+1 {
        num_occupied = (num_occupied+1)/2; // number of nonzero entries in the current level, computed by dividing previous level by 2 with rounding up
        num_nodes_above /= 2; 

        for i in num_nodes_above..num_nodes_above+num_occupied {
            let prefix : [u8; 1] = [1u8];
            hasher.input(&prefix);
            hasher.input(&params.n_bytes);
            let tree_location = i*params.hash_len;
            let children_start = 2*tree_location;
            hasher.input(&hash_tree[children_start..children_start+double_hash_len]);
            // TODO: is this the optimal way to get the hash result into the hash tree?
            hash_tree[tree_location..tree_location+params.hash_len].copy_from_slice(&hasher.result_reset());
        }
    }
    hash_tree
}


// TODO: can you make this not public but still accessible by prove?
// TODO: maybe the output type should be GenericArray rather than Vec. Does this become possible if
// we make hash_len a constant?
pub fn commit_rec(params: &Params, values: &[&[u8]], height: usize, index: usize) -> Vec<u8> {
    // We number levels from 0 at the root to params.max_depth at the leaves
    // We number nodes at each level from 0 to 2^level - 1
    // height = params.max_depth - level -- i.e., 0 at the leaves, params.max_depth at the root
    // Any node that is not an ancestor of a leaf numbered less than n has value 0 (that is, [0u8; params.hash_len])
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
        hasher.result().to_vec() // TODO: is there a way to avoid this to_vec conversion? We don't really the output type of this function to be Vec
    }
    else { // this node has no descendent leaves numbered less than n
        vec![0u8; params.hash_len]
    };
    ret
}



// TODO: ensure the changed_index is within bounds?
pub fn commit_update(params: &Params, changed_index : usize, changed_index_proof : &[u8], value_after : &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut fast_proof_update_info = vec!(0u8; params.max_depth*params.hash_len);
    let res = commit_update_helper(params, changed_index, changed_index_proof, value_after, params.max_depth, Some(&mut fast_proof_update_info));
    (res, fast_proof_update_info)
}

// TODO: how to make this not public but visible to update_proof?
pub fn commit_update_helper(params: &Params, changed_index : usize, changed_index_proof : &[u8], value_after : &[u8], update_height : usize, mut fast_proof_update_info : Option<& mut [u8]>) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    let prefix : [u8; 1] = [0u8];
    hasher.input(&prefix);
    hasher.input(&params.n_bytes);
    hasher.input(value_after);
    let mut new_com = hasher.result_reset(); 

    match fast_proof_update_info {
        None => (),
        Some(ref mut g) => g[0*params.hash_len..params.hash_len].copy_from_slice(&new_com)
    };

    let mut child_index = changed_index;

    for i in 0..update_height {
        let prefix : [u8; 1] = [1u8];
        hasher.input(&prefix);
        hasher.input(&params.n_bytes);
        if child_index & 1 == 0 { // the left child is on the path to the changed value
            hasher.input(new_com);
            hasher.input(&changed_index_proof[i*params.hash_len..(i+1)*params.hash_len]);
        }
        else {
            hasher.input(&changed_index_proof[i*params.hash_len..(i+1)*params.hash_len]);
            hasher.input(new_com);
        }
        child_index >>= 1;
        new_com = hasher.result_reset();
        if i<params.max_depth-1 {
            match fast_proof_update_info {
                None => (),
                Some(ref mut g) => g[(i+1)*params.hash_len..(i+2)*params.hash_len].copy_from_slice(&new_com)
            };
        }

    }
    new_com.to_vec() // TODO: can I avoid this to_vec conversion by having some different return type?
}

// TODO: ensure the changed_index is within bounds?
pub fn tree_update(params: &Params, changed_index : usize, value_after : &[u8], tree : &mut [u8]) {
    let mut hasher = sha2::Sha256::new();
    let prefix : [u8; 1] = [0u8];
    hasher.input(&prefix);
    hasher.input(&params.n_bytes);
    hasher.input(value_after);

    let mut ancestor_index = (1<<params.max_depth) | changed_index;

    let tree_index = ancestor_index*params.hash_len;
    tree[tree_index..tree_index+params.hash_len].copy_from_slice(&hasher.result_reset());

    let double_hash_len = 2*params.hash_len;
    while ancestor_index>1 {
        ancestor_index /= 2;
        let prefix : [u8; 1] = [1u8];
        hasher.input(&prefix);
        hasher.input(&params.n_bytes);
        let tree_location = ancestor_index * params.hash_len;
        let children_start = 2*tree_location;
        hasher.input(&tree[children_start..children_start+double_hash_len]);
        tree[tree_location..tree_location+params.hash_len].copy_from_slice(&hasher.result_reset());
    }
}
