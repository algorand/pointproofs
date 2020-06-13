use pairing::bls12_381::*;
use pairing::Engine;

// =========================
// the groups are NOT switched
/// A wrapper of BLS::G1. Groups are not switched and proof/commits are in BLS::G1
#[cfg(not(feature = "group_switched"))]
pub type PointproofsG1 = G1;
/// A wrapper of BLS::G2. Groups are not switched and proof/commits are in BLS::G1
#[cfg(not(feature = "group_switched"))]
pub type PointproofsG2 = G2;
/// A wrapper of BLS::G1Affine. Groups are not switched and proof/commits are in BLS::G1
#[cfg(not(feature = "group_switched"))]
pub type PointproofsG1Affine = G1Affine;
/// A wrapper of BLS::G2Affine. Groups are not switched and proof/commits are in BLS::G1
#[cfg(not(feature = "group_switched"))]
pub type PointproofsG2Affine = G2Affine;

#[cfg(not(feature = "group_switched"))]
pub const POINTPROOFSG1_LEN: usize = 48;
#[cfg(not(feature = "group_switched"))]
pub const POINTPROOFSG2_LEN: usize = 96;

/// A wrapper of BLS::pairing_product. Groups are switched and proof/commits are in BLS::G1
#[cfg(not(feature = "group_switched"))]
pub(crate) fn pointproofs_pairing(p1: PointproofsG1Affine, q1: PointproofsG2Affine) -> Fq12 {
    Bls12::pairing(p1, q1)
}
/// A wrapper of BLS::pairing_product. Groups are switched and proof/commits are in BLS::G1
#[cfg(not(feature = "group_switched"))]
pub(crate) fn pointproofs_pairing_product(
    p1: PointproofsG1Affine,
    q1: PointproofsG2Affine,
    p2: PointproofsG1Affine,
    q2: PointproofsG2Affine,
) -> Fq12 {
    Bls12::pairing_product(p1, q1, p2, q2)
}
/// A wrapper of BLS::pairing_multi_product. Groups are switched and proof/commits are in BLS::G1
#[cfg(not(feature = "group_switched"))]
pub(crate) fn pointproofs_pairing_multi_product(
    g1_vec: &[PointproofsG1Affine],
    g2_vec: &[PointproofsG2Affine],
) -> Fq12 {
    Bls12::pairing_multi_product(g1_vec, g2_vec)
}

/// Size for serialized commitment.
#[cfg(not(feature = "group_switched"))]
pub const COMMIT_LEN: usize = 49;

/// Size for serialized proof.
#[cfg(not(feature = "group_switched"))]
pub const PROOF_LEN: usize = 49;

// =========================
// the groups are switched

/// A wrapper of BLS::G2. Groups are switched and proof/commits are in BLS::G2
#[cfg(feature = "group_switched")]
pub type PointproofsG1 = G2;
/// A wrapper of BLS::G1. Groups are switched and proof/commits are in BLS::G2
#[cfg(feature = "group_switched")]
pub type PointproofsG2 = G1;
/// A wrapper of BLS::G2Affine. Groups are switched and proof/commits are in BLS::G2
#[cfg(feature = "group_switched")]
pub type PointproofsG1Affine = G2Affine;
/// A wrapper of BLS::G1Affine. Groups are switched and proof/commits are in BLS::G2
#[cfg(feature = "group_switched")]
pub type PointproofsG2Affine = G1Affine;

#[cfg(feature = "group_switched")]
pub const POINTPROOFSG1_LEN: usize = 96;
#[cfg(feature = "group_switched")]
pub const POINTPROOFSG2_LEN: usize = 48;

/// A wrapper of BLS::pairing. Groups are switched and proof/commits are in BLS::G2
#[cfg(feature = "group_switched")]
pub(crate) fn pointproofs_pairing(p1: PointproofsG1Affine, q1: PointproofsG2Affine) -> Fq12 {
    Bls12::pairing(q1, p1)
}
/// A wrapper of BLS::pairing_product. Groups are switched and proof/commits are in BLS::G2
#[cfg(feature = "group_switched")]
pub(crate) fn pointproofs_pairing_product(
    p1: PointproofsG1Affine,
    q1: PointproofsG2Affine,
    p2: PointproofsG1Affine,
    q2: PointproofsG2Affine,
) -> Fq12 {
    Bls12::pairing_product(q1, p1, q2, p2)
}
/// A wrapper of BLS::pairing_multi_product. Groups are switched and proof/commits are in BLS::G2
#[cfg(feature = "group_switched")]
pub(crate) fn pointproofs_pairing_multi_product(
    g1_vec: &[PointproofsG1Affine],
    g2_vec: &[PointproofsG2Affine],
) -> Fq12 {
    Bls12::pairing_multi_product(g2_vec, g1_vec)
}


/// Size for serialized commitment.
#[cfg(feature = "group_switched")]
pub const COMMIT_LEN: usize = 97;

/// Size for serialized proof.
#[cfg(feature = "group_switched")]
pub const PROOF_LEN: usize = 97;
