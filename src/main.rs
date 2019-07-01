#![feature(test)]
extern crate test;
extern crate pairing;
extern crate ff;
extern crate sha2;

pub mod veccom_pairings;
pub mod veccom_merkle;

pub mod run_veccom_pairings;
pub mod run_veccom_merkle;

fn main () {
    run_veccom_merkle::run_veccom_merkle();
}

