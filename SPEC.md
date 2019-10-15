# Pairing based vector commitment Signature
<!---
This file is still under construction
--->


* Link to the paper: TBD



## Ciphersuites

``` rust
/// Ciphersuite is a wrapper of u8
pub type Ciphersuite = u8;
```

* Methods:

  * `check_ciphersuite(Ciphersuite) -> bool` checks if the ciphersuite is supported by the current version of the code.


## System Parameters

``` rust
pub struct SystemParam {
    ciphersuite: Ciphersuite,
    n: usize,
    pp_len: usize,
}
```

* Methods:

  ```rust
  get_system_paramter(Ciphersuite) -> Result<SystemParam, String>
  ```
  * Input: ciphersuite identifier
  * Output: a system parameter
  * Error: ciphersuite is not supported


## ProverParam and VerifierParam

``` rust
pub struct ProverParams {
    ciphersuite: Ciphersuite,
    /// 2n G1 elements
    generators: Vec<G1Affine>,
    /// various length pre-computed G1 elements;
    /// length depending on cipersuite is
    precomp: Vec<G1Affine>,
}
```

``` rust
pub struct VerifierParams {
    ciphersuite: Ciphersuite,
    /// n G2 elements
    generators: Vec<G2Affine>,
    /// 1 Gt element
    gt_elt: Fq12,
}
```

* Methods:
  ``` rust
  fn paramgen_from_seed<Blob: AsRef<[u8]>>(
      seed: Blob,
      ciphersuite: Ciphersuite,
  ) -> Result<(ProverParams, VerifierParams), String> {
  ```
  * Input: a seed
  * Input: ciphersuite identifier
  * Output: prover parameter and verifier parameter
  * Error: ciphersuite is not supported
  * Error: seed is too short


  ``` rust
  fn serialize<W: std::io::Write>(
      &self,
      writer: &mut W,
      compressed: Compressed,
  ) -> std::io::Result<()>
  ```
  * Input: either a `ProverParams` or a `VerifierParam`
  * Input: a writable buffer
  * Input: a flag whether to compress the group point or not
  * Output: none
  * Error: ciphersuite is not supported
  * Error: ciphersuite does not match #elements in parameters
