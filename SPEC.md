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

  ``` rust
  fn check_ciphersuite(Ciphersuite) -> bool
  ```
  * Input: ciphersuite identifier
  * Output: checks if the ciphersuite is supported by the current version of the code.


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
  fn get_system_paramter(Ciphersuite) -> Result<SystemParam, String>
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
  ) -> Result<(ProverParams, VerifierParams), String>
  ```
  * Input: a seed
  * Input: ciphersuite identifier
  * Output: prover parameter and verifier parameter
  * Error: ciphersuite is not supported
  * Error: seed is too short


  ``` rust
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>
  ```
  * Input: either a `ProverParams` or a `VerifierParam`
  * Input: a writable buffer
  * Input: a flag whether to compress the group point or not
  * Output: none
  * Error: ciphersuite is not supported
  * Error: ciphersuite does not match #elements in parameters
  * Error: serialization fails
  * Steps: serialize the parameters into a blob
    1. For `ProverParams`, convert `ciphersuite id | generators | [pre_compute]` to bytes
    2. For `VerifierParam`, convert  `ciphersuite id | generators | gt_element` to bytes


  ``` rust
  fn deserialize<R: Read>(reader: &mut R, compressed: bool) -> Result<Self>
  ```
  * Input: a readeble buffer
  * Input: a flag whether the group elements are expected to be compressed or not
  * Output: either a `ProverParams` or a `VerifierParam`
  * Error: ciphersuite is not supported
  * Error: ciphersuite does not match #elements in parameters
  * Error: encoded buffer has a different compressness than specified
  * Error: deserialization fails
  * Steps: deserialize the blob into parameters
    1. For `ProverParams`, convert bytes to `ciphersuite id | generators | [pre_compute]`
    2. For `VerifierParam`, convert bytes to `ciphersuite id | generators | gt_element`

## Commitment    

  ``` rust
  pub struct Commitment {
      ciphersuite: Ciphersuite,
      commit: G1,
  }
  ```

* Methods:

  ``` rust
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>
  ```
  * Input: a `Commitment`
  * Input: a writable buffer
  * Input: a flag whether to compress the group point or not
  * Output: none
  * Error: ciphersuite is not supported
  * Error: serialization fails
  * Steps: convert `ciphersuite|commit` to bytes


  ``` rust
  fn deserialize<R: Read>(reader: &mut R, compressed: bool) -> Result<Self>
  ```
  * Input: a readeble buffer
  * Input: a flag whether the group elements are expected to be compressed or not
  * Output: a `Commitment`
  * Error: ciphersuite is not supported
  * Error: encoded buffer has a different compressness than specified
  * Error: deserialization fails
  * Steps: convert bytes to `ciphersuite|commit`


  ``` rust
  pub fn new<Blob: AsRef<[u8]>>(
      prover_params: &ProverParams,
      values: &[Blob],
  ) -> Result<Self, String>
  ```
  * Input: a `ProverParam`
  * Input: the values to commit to; as a slice of `&[u8]`
  * Output: a `Commitment`
  * Error: ciphersuite is not supported
  * Error: ciphersuite does not match #elements in parameters


  ``` rust
  pub fn update<Blob: AsRef<[u8]>>(
        &mut self,
        prover_params: &ProverParams,
        changed_index: usize,
        value_before: Blob,
        value_after: Blob,
    ) -> Result<(), String>
  ```
  * Input: self, a `Commitment`
  * 
