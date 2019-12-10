use pairings::param::paramgen_from_seed;

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
