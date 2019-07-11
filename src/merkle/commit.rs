use super::Params;
use sha2::Digest;

pub fn commit_no_tree(params: &Params, values: &[Vec<u8>]) -> Vec<u8> {
    // TODO: error handling if the prover params.n is not equal to values length
    // TODO: figure out if the input for values is the right one to use
    // TODO: is this the correct output type?
    commit_rec(params, values, params.max_depth, 0)
}

// TODO: error handling if the prover params.n is not equal to values length
// TODO: figure out if the input for values is the right one to use
// TODO: is this the correct return type?
// TODO: there's got to be a better way than all these to_vec conversions
pub fn commit_with_tree(params: &Params, values: &[Vec<u8>]) -> (Vec<Vec<u8>>) {
    // node i at depth k is stored in location 2^k+i (like a heap)
    let mut num_nodes_above = 1<<params.max_depth; // number of nodes above the current level, plus 1 (where current level starts at the leaves)
    let num_leaves = ((params.n+1)/2)*2; // round up n to the nearest even number
    let mut hash_tree = Vec::with_capacity(num_nodes_above+num_leaves);// vec!(Vec::with_capacity(0); num_nodes_above+num_leaves);

    for i in 0 .. params.n {
        let mut hasher = sha2::Sha256::new();
        let prefix : [u8; 1] = [0u8];
        hasher.input(&prefix);
        hasher.input(&params.n_bytes);
        hasher.input(&values[i]);
        hash_tree[num_nodes_above+i] = hasher.result().to_vec();
    }
    if params.n & 1 == 1 { // if n is odd, add a 0 leaf
        hash_tree[num_nodes_above + params.n] = [0u8; 32].to_vec();
    }


    let mut num_occupied = num_leaves;
    for _height in 1..params.max_depth+1 {
        num_occupied = (num_occupied+1)/2; // number of nonzero entries in the current level, computed by dividing previous level by 2 with rounding up
        num_nodes_above /= 1; 

        for i in 0..num_occupied {
            let mut hasher = sha2::Sha256::new();
            let prefix : [u8; 1] = [1u8];
            hasher.input(&prefix);
            hasher.input(&params.n_bytes);
            let array_index = num_nodes_above + i;
            hasher.input(&hash_tree[2*array_index]);
            hasher.input(&hash_tree[2*array_index+1]);
            hash_tree[num_nodes_above+i] = hasher.result().to_vec();
        }
        if num_occupied & 1 == 1 { // if num_occupied is odd, add a 0 node
            hash_tree[num_nodes_above + num_occupied] = [0u8; 32].to_vec();

        }
    }
    hash_tree
}
/*
fn print_bytes(b : &[u8])->String {
    let mut ret = "".to_string();
    for i in 0..b.len() {
        ret = ret + &format!("{:02x}", b[i]);
    }
    ret
}*/

// TODO: can you make this not public but still accessible by prove?
pub fn commit_rec(params: &Params, values: &[Vec<u8>], height: usize, index: usize) -> Vec<u8> {
    // We number levels from 0 at the root to params.max_depth at the leaves
    // We number nodes at each level from 0 to 2^level - 1
    // height = params.max_depth - level -- i.e., 0 at the leaves, params.max_depth at the root
    // Any node that is not an ancestor of a leaf numbered less than n has value 0 (that is, [0u8; 32])
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
        hasher.result().to_vec() // TODO: is this the best way to obtain the output and is this the output type we want?
    }
    else { // this node has no descendent leaves numbered less than n
        [0u8; 32].to_vec()
    };
    //println!("{} {} {}", height, index, print_bytes(&ret));
    ret
}



// TODO: ensure the changed_index are within bounds?
pub fn commit_update(params: &Params, changed_index : usize, changed_index_proof : &[u8], value_after : &[u8]) -> Vec<u8> {
    let mut fast_proof_update_info = vec!(0u8; params.max_depth*params.hash_len);
    commit_update_helper(params, changed_index, changed_index_proof, value_after, params.max_depth, Some(&mut fast_proof_update_info))
}

// TODO: how to make this not public but visible to update_proof?
pub fn commit_update_helper(params: &Params, changed_index : usize, changed_index_proof : &[u8], value_after : &[u8], update_height : usize, fast_proof_update_info : Option<& mut [u8]>) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    let prefix : [u8; 1] = [0u8];
    hasher.input(&prefix);
    hasher.input(&params.n_bytes);
    hasher.input(value_after);
    let mut new_com = hasher.result().to_vec();

    // f is necessary because we can't match fast_proof_update_info directly, because that causes a move of g
    // and then it cannot be used later in the loop per compiler complaint
    let mut f = fast_proof_update_info;
    match  &mut f  {
        None => (),
        Some(g) => g[0*params.hash_len..params.hash_len].copy_from_slice(&new_com)
    };

    let mut child_index = changed_index;

    for i in 0..update_height {
        let mut hasher = sha2::Sha256::new();
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
        new_com = hasher.result().to_vec();
        if i<params.max_depth-1 {
            match  &mut f  {
                None => (),
                Some(g) => g[(i+1)*params.hash_len..(i+2)*params.hash_len].copy_from_slice(&new_com)
            };
        }

    }
    new_com
}

pub fn tree_update(params: &Params, changed_index : usize, value_after : &[u8], tree : &mut Vec<Vec<u8>>) {
    let mut hasher = sha2::Sha256::new();
    let prefix : [u8; 1] = [0u8];
    hasher.input(&prefix);
    hasher.input(&params.n_bytes);
    hasher.input(value_after);

    let mut ancestor_index = (1<<params.max_depth) | changed_index;

    tree[ancestor_index] = hasher.result().to_vec();

    while ancestor_index>1 {
        ancestor_index /=2;
        let mut hasher = sha2::Sha256::new();
        let prefix : [u8; 1] = [1u8];
        hasher.input(&prefix);
        hasher.input(&params.n_bytes);
        hasher.input(&tree[ancestor_index*2]);
        hasher.input(&tree[ancestor_index*2+1]);

        tree[ancestor_index] = hasher.result().to_vec();
    }
}
