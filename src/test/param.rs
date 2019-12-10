use pairing::serdes::SerDes;
use pairings::param::paramgen_from_seed;
use pairings::{ProverParams, VerifierParams};

#[test]
fn test_param() {
    let n_array = [32, 256];
    for n in n_array.iter() {
        let (pp1, vp1) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, *n).unwrap();

        let (pp2, vp2) = paramgen_from_seed(
            "This is Leo's Second Favourite very very very long Seed",
            0,
            *n,
        )
        .unwrap();

        assert!(pp1.check_parameters(&vp1));
        assert!(pp2.check_parameters(&vp2));

        // must fails
        assert!(!pp1.check_parameters(&vp2));
        assert!(!pp2.check_parameters(&vp1));
    }
}

#[test]
fn test_serdes_prover_param() {
    let n_array = [32, 256];
    for n in n_array.iter() {
        let (mut prover_params, _verifier_params) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, *n).unwrap();

        let mut buf: Vec<u8> = vec![];
        assert!(prover_params.serialize(&mut buf, true).is_ok());
        let mut invalid_buf = buf.clone();
        let mut valid_buf = buf.clone();
        for i in 0u8..8 {
            invalid_buf[i as usize] = i;
        }
        let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(prover_params, prover_params_recover);
        assert!(ProverParams::deserialize(&mut invalid_buf[..].as_ref(), true).is_err());
        assert!(ProverParams::deserialize(&mut valid_buf[..].as_ref(), false).is_err());

        prover_params.precomp_3();
        let mut buf: Vec<u8> = vec![];
        assert!(prover_params.serialize(&mut buf, true).is_ok());

        let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(prover_params, prover_params_recover);

        prover_params.precomp_256();
        let mut buf: Vec<u8> = vec![];
        assert!(prover_params.serialize(&mut buf, true).is_ok());

        let prover_params_recover = ProverParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(prover_params, prover_params_recover);
    }
}

#[test]
fn test_serdes_verifier_param() {
    let n_array = [32, 256];
    for n in n_array.iter() {
        let (_prover_params, verifier_params) =
            paramgen_from_seed("This is Leo's Favourite very very very long Seed", 0, *n).unwrap();

        let mut buf: Vec<u8> = vec![];
        assert!(verifier_params.serialize(&mut buf, true).is_ok());

        let verifier_params_recover =
            VerifierParams::deserialize(&mut buf[..].as_ref(), true).unwrap();
        assert_eq!(verifier_params, verifier_params_recover);
    }
}
