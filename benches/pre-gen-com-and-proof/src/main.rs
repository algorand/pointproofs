extern crate pairing_plus as pairing;
extern crate veccom;

use pairing::serdes::SerDes;
use pairing::CurveProjective;
use std::time::Duration;
use veccom::pairings::*;


// parameters
// n: public parameters
const N_ARRAY: [usize; 3] = [256, 1024, 4096];
// t: number of commits for each test
const MAX_C: usize = 16; // for each test, we have no more than 16 commits
// k: number of proofs for each commit
const MAX_P: usize = 16; // for each commitment, generate no more than 16 proofs


fn main() {




    for t in N_ARRAY.iter() {
        let n = *t;
        println!("generating a commitment for n = {}", n);

        // read the parameters
        let file_name = format!("../pre-gen-param/{}.param", n);
        let mut file = std::fs::File::open(file_name).unwrap();
        let (pp, _vp) = paramgen::read_param(&mut file).unwrap();

        // initiate the values
        for com_index in 0..MAX_C {
            let mut init_values = Vec::with_capacity(n);
            for j in 0..n {
                let s = format!("this is message: commit {}, index {}", com_index, j);
                init_values.push(s.into_bytes());
            }

            let mut values: Vec<&[u8]> = Vec::with_capacity(n);
            for e in init_values.iter().take(n) {
                values.push(&e);
            }
            // generete the commitment
            pre_gen_commit_helper(&pp, &values, com_index);

            // generate the proofs
            pre_gen_proof_helper(&pp, &values, com_index);

        }
        println!("finished\n\n");
    }
    println!("Hello, world!");
}

fn pre_gen_commit_helper(prover_params: &ProverParams, values: &Vec<&[u8]>, com_index: usize) {
    let n = prover_params.n;

    let file_name = format!("tmp/n_{}_com_{}.commit", n, com_index);
    let mut file = std::fs::File::create(file_name).unwrap();

    Commitment::new(prover_params, &values)
        .unwrap()
        .serialize(&mut file, true)
        .unwrap();
}


fn pre_gen_proof_helper(prover_params: &ProverParams, values: &Vec<&[u8]>, com_index: usize) {
    let n = prover_params.n;
    for proof_index in 0..MAX_P {
        let file_name = format!("tmp/n_{}_com_{}_proof_{}.proof", n, com_index, proof_index);
        let mut file = std::fs::File::create(file_name).unwrap();

        Proof::new(prover_params, &values, proof_index)
            .unwrap()
            .serialize(&mut file, true)
            .unwrap();
    }

}
