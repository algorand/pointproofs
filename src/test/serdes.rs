use pairing::serdes::SerDes;
use pairing::CurveProjective;
use pairings::param::paramgen_from_seed;
use pairings::pointproofs_groups::*;
use pairings::*;

#[test]
fn test_serdes_prover_param() {
    let n_array = [16];
    for n in n_array.iter() {
        let (mut prover_params, _verifier_params) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, *n).unwrap();

        let mut buf: Vec<u8> = vec![];
        assert!(prover_params.serialize(&mut buf, false).is_err());
        assert!(prover_params.serialize(&mut buf, true).is_ok());

        assert_eq!(buf.len(), 9 + n * POINTPROOFSG1_LEN * 2);

        let mut invalid_buf = buf.clone();
        let mut valid_buf = buf.clone();
        for i in 0u8..8 {
            invalid_buf[i as usize] = i;
        }
        let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(prover_params, prover_params_recover);
        assert!(ProverParams::deserialize(&mut invalid_buf[..].as_ref(), true).is_err());
        assert!(ProverParams::deserialize(&mut invalid_buf[..].as_ref(), false).is_err());
        assert!(ProverParams::deserialize(&mut valid_buf[..].as_ref(), false).is_err());

        prover_params.precomp_3();
        let mut buf: Vec<u8> = vec![];
        assert!(prover_params.serialize(&mut buf, false).is_err());
        assert!(prover_params.serialize(&mut buf, true).is_ok());

        assert!(ProverParams::deserialize(&mut buf[..].as_ref(), false).is_err());
        let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(prover_params, prover_params_recover);

        prover_params.precomp_256();
        let mut buf: Vec<u8> = vec![];
        assert!(prover_params.serialize(&mut buf, false).is_err());
        assert!(prover_params.serialize(&mut buf, true).is_ok());
        assert!(ProverParams::deserialize(&mut buf[..].as_ref(), false).is_err());
        let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(prover_params, prover_params_recover);
    }
}

#[test]
#[ignore]
fn test_serdes_prover_param_slow() {
    let n_array = [32, 256];
    for n in n_array.iter() {
        let (mut prover_params, _verifier_params) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, *n).unwrap();

        let mut buf: Vec<u8> = vec![];
        assert!(prover_params.serialize(&mut buf, false).is_err());
        assert!(prover_params.serialize(&mut buf, true).is_ok());

        assert_eq!(buf.len(), 9 + n * POINTPROOFSG1_LEN * 2);

        let mut invalid_buf = buf.clone();
        let mut valid_buf = buf.clone();
        for i in 0u8..8 {
            invalid_buf[i as usize] = i;
        }
        let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(prover_params, prover_params_recover);
        assert!(ProverParams::deserialize(&mut invalid_buf[..].as_ref(), true).is_err());
        assert!(ProverParams::deserialize(&mut invalid_buf[..].as_ref(), false).is_err());
        assert!(ProverParams::deserialize(&mut valid_buf[..].as_ref(), false).is_err());

        prover_params.precomp_3();
        let mut buf: Vec<u8> = vec![];
        assert!(prover_params.serialize(&mut buf, false).is_err());
        assert!(prover_params.serialize(&mut buf, true).is_ok());

        assert!(ProverParams::deserialize(&mut buf[..].as_ref(), false).is_err());
        let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(prover_params, prover_params_recover);

        prover_params.precomp_256();
        let mut buf: Vec<u8> = vec![];
        assert!(prover_params.serialize(&mut buf, false).is_err());
        assert!(prover_params.serialize(&mut buf, true).is_ok());
        assert!(ProverParams::deserialize(&mut buf[..].as_ref(), false).is_err());
        let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(prover_params, prover_params_recover);
    }
}

#[test]
fn test_serdes_verifier_param() {
    let n_array = [16];
    for n in n_array.iter() {
        let (_prover_params, verifier_params) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, *n).unwrap();

        let mut buf: Vec<u8> = vec![];
        assert!(verifier_params.serialize(&mut buf, false).is_err());
        assert!(verifier_params.serialize(&mut buf, true).is_ok());
        let len = buf.len();

        assert_eq!(len, 585 + n * POINTPROOFSG2_LEN);

        assert!(VerifierParams::deserialize(&mut buf[..].as_ref(), false).is_err());
        let verifier_params_recover =
            VerifierParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(verifier_params, verifier_params_recover);

        let mut valid_buf1 = vec![0; len];
        assert!(VerifierParams::deserialize(&mut valid_buf1[..].as_ref(), true).is_err());
        assert!(VerifierParams::deserialize(&mut valid_buf1[..].as_ref(), false).is_err());
        let mut invalid_buf1 = vec![1; len];
        let mut invalid_buf2 = vec![2; len];
        assert!(VerifierParams::deserialize(&mut invalid_buf1[..].as_ref(), true).is_err());
        assert!(VerifierParams::deserialize(&mut invalid_buf1[..].as_ref(), false).is_err());
        assert!(VerifierParams::deserialize(&mut invalid_buf2[..].as_ref(), true).is_err());
        assert!(VerifierParams::deserialize(&mut invalid_buf2[..].as_ref(), false).is_err());
    }
}

#[test]
#[ignore]
fn test_serdes_verifier_param_slow() {
    let n_array = [32, 256];
    for n in n_array.iter() {
        let (_prover_params, verifier_params) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, *n).unwrap();

        let mut buf: Vec<u8> = vec![];
        assert!(verifier_params.serialize(&mut buf, false).is_err());
        assert!(verifier_params.serialize(&mut buf, true).is_ok());
        let len = buf.len();

        assert_eq!(len, 585 + n * POINTPROOFSG2_LEN);

        assert!(VerifierParams::deserialize(&mut buf[..].as_ref(), false).is_err());
        let verifier_params_recover =
            VerifierParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(verifier_params, verifier_params_recover);

        let mut valid_buf1 = vec![0; len];
        assert!(VerifierParams::deserialize(&mut valid_buf1[..].as_ref(), true).is_err());
        assert!(VerifierParams::deserialize(&mut valid_buf1[..].as_ref(), false).is_err());
        let mut invalid_buf1 = vec![1; len];
        let mut invalid_buf2 = vec![2; len];
        assert!(VerifierParams::deserialize(&mut invalid_buf1[..].as_ref(), true).is_err());
        assert!(VerifierParams::deserialize(&mut invalid_buf1[..].as_ref(), false).is_err());
        assert!(VerifierParams::deserialize(&mut invalid_buf2[..].as_ref(), true).is_err());
        assert!(VerifierParams::deserialize(&mut invalid_buf2[..].as_ref(), false).is_err());
    }
}

#[test]
fn test_serdes_commit() {
    let mut buf: Vec<u8> = vec![];
    let valid_commit = Commitment {
        ciphersuite: 0,
        commit: PointproofsG1::one(),
    };
    assert!(valid_commit.serialize(&mut buf, false).is_err());
    assert!(valid_commit.serialize(&mut buf, true).is_ok());
    let len = buf.len();
    let valid_commit_recover = match Commitment::deserialize(&mut buf[..].as_ref(), true) {
        Ok(p) => p,
        Err(e) => panic!("Error deserilization: {}", e),
    };
    assert_eq!(valid_commit, valid_commit_recover);
    assert!(Commitment::deserialize(&mut buf[..].as_ref(), false).is_err());

    let invalid_commit = Commitment {
        ciphersuite: 1,
        commit: PointproofsG1::one(),
    };
    assert!(invalid_commit.serialize(&mut buf, true).is_err());

    let mut invalid_buf1 = vec![0; len];
    let mut invalid_buf2 = vec![1; len];
    assert!(Commitment::deserialize(&mut invalid_buf1[..].as_ref(), true).is_err());
    assert!(Commitment::deserialize(&mut invalid_buf1[..].as_ref(), false).is_err());
    assert!(Commitment::deserialize(&mut invalid_buf2[..].as_ref(), true).is_err());
    assert!(Commitment::deserialize(&mut invalid_buf2[..].as_ref(), false).is_err());
}

#[test]
fn test_serdes_proof() {
    let mut buf: Vec<u8> = vec![];
    let valid_proof = Proof {
        ciphersuite: 0,
        proof: PointproofsG1::one(),
    };

    assert!(valid_proof.serialize(&mut buf, true).is_ok());
    let len = buf.len();
    let valid_proof_recover = match Proof::deserialize(&mut buf[..].as_ref(), true) {
        Ok(p) => p,
        Err(e) => panic!("Error deserilization: {}", e),
    };
    assert_eq!(valid_proof, valid_proof_recover);
    assert!(Proof::deserialize(&mut buf[..].as_ref(), false).is_err());

    let invalid_proof = Proof {
        ciphersuite: 1,
        proof: PointproofsG1::one(),
    };
    assert!(invalid_proof.serialize(&mut buf, true).is_err());

    let mut invalid_buf1 = vec![0; len];
    let mut invalid_buf2 = vec![1; len];
    assert!(Proof::deserialize(&mut invalid_buf1[..].as_ref(), true).is_err());
    assert!(Proof::deserialize(&mut invalid_buf1[..].as_ref(), false).is_err());
    assert!(Proof::deserialize(&mut invalid_buf2[..].as_ref(), true).is_err());
    assert!(Proof::deserialize(&mut invalid_buf2[..].as_ref(), false).is_err());
}
