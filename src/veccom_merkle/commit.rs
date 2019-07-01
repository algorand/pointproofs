use super::Params;
use sha2::Digest;

pub fn commit(params: &Params, values: &[Vec<u8>]) -> Vec<u8> {
    println!("in commit");
    // TODO: error handling if the prover params length is not equal to values length
    // TODO: figure out if the input for values is the right one to use
    // TODO: is this the correct output type?
    commit_rec(params, values, 0, 0)
}

fn print_bytes(b : &[u8])->String {
    let mut ret = "".to_string();
    for i in 0..b.len() {
        ret = ret + &format!("{:02x}", b[i]);
    }
    ret
}
// TODO: can you make this not public but still accessible by prove?
pub fn commit_rec(params: &Params, values: &[Vec<u8>], level: usize, index: usize) -> Vec<u8> {
    // We number levels from 0 at the root to params.max_depth at the leaves
    // We number nodes at each level from 0 to 2^level - 1
    let height = params.max_depth-level;
    let num_occupied = (params.n+(1<<height)-1)>>height; // divide params.n by 2^height with rouding up to get number of occupied tree cells in this level
    let ret = if index < num_occupied {
        let mut hasher = sha2::Sha256::new();
        if level == params.max_depth {
            let prefix : [u8; 1] = [0u8];
            hasher.input(&prefix);
            hasher.input(&params.n_bytes);
            hasher.input(&values[index]);
        }
        else {
            let prefix : [u8; 1] = [1u8];
            hasher.input(&prefix);
            hasher.input(&params.n_bytes);
            hasher.input(&commit_rec(params, values, level+1, index*2));
            hasher.input(&commit_rec(params, values, level+1, index*2+1));
        }
        hasher.result().to_vec() // TODO: is this the best way to obtain the output and is this the output type we want?
    }
    else { // this node has no children numbered less than n
        [0u8; 32].to_vec()
    };
    println!("    {} {} {} {} {}", params.n, params.max_depth, level, index, print_bytes(&ret));
    ret

}


pub fn commit_update(params: &Params, changed_index : usize, changed_index_proof : &[Vec<u8>], value_after : &[u8]) -> Vec<u8> {
    println!("In commit update for index {}", changed_index);
    commit_update_helper(params, changed_index, changed_index_proof, value_after, params.max_depth)
}

// TODO: how to make this not public but visible to update_proof?
pub fn commit_update_helper(params: &Params, changed_index : usize, changed_index_proof : &[Vec<u8>], value_after : &[u8], update_height : usize) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    let prefix : [u8; 1] = [0u8];
    hasher.input(&prefix);
    hasher.input(&params.n_bytes);
    hasher.input(value_after);
    let mut new_com = hasher.result().to_vec();
    let mut child_index = changed_index;
    println!("    {} {}", params.max_depth, print_bytes(&new_com));

    for i in 0..update_height {
        let mut hasher = sha2::Sha256::new();
        let prefix : [u8; 1] = [1u8];
        hasher.input(&prefix);
        hasher.input(&params.n_bytes);
        if child_index & 1 == 0 { // the left child is on the path to the changed value
            hasher.input(new_com);
            hasher.input(&changed_index_proof[i]);
        }
        else {
            hasher.input(&changed_index_proof[i]);
            hasher.input(new_com);
        }
        child_index >>= 1;
        new_com = hasher.result().to_vec();
        println!("    {} {}", params.max_depth-i-1, print_bytes(&new_com));
    }
    new_com
}

/*
// convert a proof (which is a projective G1 element) into a string of 48 bytes
// Copied from the bls library
pub fn convert_commitment_to_bytes (commitment: &G1) -> [u8; 48] {
    let s = pairing::bls12_381::G1Compressed::from_affine(commitment.into_affine());
    let mut out: [u8; 48] = [0; 48];
    out.copy_from_slice(s.as_ref());
    out
}
  
// take an array of 48 bytes and output a proof
// Copied from the bls library
pub fn convert_bytes_to_commitment (input : &[u8; 48]) -> G1 {
    let mut commitment_compressed = G1Compressed::empty();
    commitment_compressed
        .as_mut()
        .copy_from_slice(input);
    let commitment_affine = commitment_compressed.into_affine().unwrap();
    commitment_affine.into_projective()
}
*/