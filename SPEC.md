# Pairing based vector commitment Signature
<!---
This file is still under construction
--->


* Link to the paper: TBD



## Ciphersuites

* Definitions

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
  * Note: currently only support `ciphersuite == 0`

## Groups

* Definitions

  ``` rust
  /// the VeccomG1 and VeccomG2 are switched to improve verification speed
  /// VeccomG1 represents G1 in the paper, and is mapped to bls12-381::G2
  type VeccomG1 = G2;
  type VeccomG2 = G1;
  type VeccomG1Affine = G2Affine;
  type VeccomG2Affine = G1Affine;
  ```


## ProverParam and VerifierParam

* Definitions
  ``` rust
  pub struct ProverParams {
      pub ciphersuite: Ciphersuite,
      pub n: usize,
      pub generators: Vec<VeccomG1Affine>,
      pub pp_len: usize,
      pub precomp: Vec<VeccomG1Affine>,
  }
  ```

  ``` rust
  pub struct VerifierParams {
      ciphersuite: Ciphersuite,
      pub n: usize,
      generators: Vec<VeccomG2Affine>,
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
  * Note: This function is only used for testing. For deployment, use `veccom_paramgen` trait for parameters.

  ``` rust
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>
  ```
  * Input: either a `ProverParams` or a `VerifierParam`
  * Input: a writable buffer
  * Input: a flag whether to compress the group point or not; must be false
  * Output: none
  * Error: ciphersuite is not supported
  * Error: ciphersuite does not match #elements in parameters
  * Error: serialization fails
  * Steps: serialize the parameters into a blob
    1. For `ProverParams`, convert `|ciphersuite id | n | generators | pp_len | [pre_compute]` to bytes
    2. For `VerifierParam`, convert  `|ciphersuite id | n | generators | pp_len | [pre_compute]` to bytes


  ``` rust
  fn deserialize<R: Read>(reader: &mut R, compressed: bool) -> Result<Self>
  ```
  * Input: a readeble buffer
  * Input: a flag whether the group elements are expected to be compressed or not; must be false
  * Output: either a `ProverParams` or a `VerifierParam`
  * Error: ciphersuite is not supported
  * Error: ciphersuite does not match #elements in parameters
  * Error: encoded buffer has a different compressness than specified
  * Error: deserialization fails
  * Steps: deserialize the blob into parameters
    1. For `ProverParams`, convert bytes to `|ciphersuite id | n | generators | pp_len | [pre_compute]`
    2. For `VerifierParam`, convert bytes to `|ciphersuite id | n | generators | pp_len | [pre_compute]`

## Commitment    

* Definitions
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
  * Input: a flag whether to compress the group point or not; must be false
  * Output: none
  * Error: ciphersuite is not supported
  * Error: serialization fails
  * Steps: convert `| ciphersuite | commit |` to bytes


  ``` rust
  fn deserialize<R: Read>(reader: &mut R, compressed: bool) -> Result<Self>
  ```
  * Input: a readeble buffer
  * Input: a flag whether the group elements are expected to be compressed or not; must be false
  * Output: a `Commitment`
  * Error: ciphersuite is not supported
  * Error: encoded buffer has a different compressness than specified
  * Error: deserialization fails
  * Steps: convert bytes to `| ciphersuite | commit |`


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
  * Input: a `ProverParam`
  * Input: the `index` to be updated
  * Input: the original value
  * Input: the value updated to
  * Output: mutate self to the updated commit
  * Error: ciphersuite is not supported
  * Error: index out of range


## hashes

* veccom's hash to field

  ``` rust
  // hash_to_field_veccom use SHA 512 to hash a blob into a non-zero field element
  pub fn hash_to_field_veccom<Blob: AsRef<[u8]>>(input: Blob) -> Fr
  ```
  * Steps:
    1. hash `input` into `64` bytes array `data`
    2. convert `data` into a 512 bits integer `a = os2ip(data)`
    3. `t = a mod r` where `r` is the group order
    4. if `t == 0` return 1, else return `t`
  * Note: always returns a non-zero field element. The output should be IND from uniform.

* hash to t_j

  ``` rust
  pub fn hash_to_tj<Blob: AsRef<[u8]>>(
      commits: &[Commitment],
      set: &[Vec<usize>],
      value_sub_vector: &[Vec<Blob>],
      n: usize,
  ) -> Result<Vec<FrRepr>, String>
  ```
  * Input: a list of k commitments
  * Input: a list of k * x indices, for which we need to generate t_j
  * Input: Value: a list of k * x messages that is committed to
  * Output: a list of k field elements
  * Error: ciphersuite id not supported
  * Error: lengths do no match
  * Steps:
    1. `tmp = {C | S | m[S]} for i \in [0 .. commit.len-1]`
    2. `digest = SHA512(tmp)`
    3. for `0 <= i < commits.len()`, `res[i] = hash_to_field_veccom(i, digest)`


* hash to t_i

  ``` rust
  pub fn hash_to_ti_fr<Blob: AsRef<[u8]>>(
    commit: &Commitment,
    set: &[usize],
    value_sub_vector: &[Blob],
    n: usize,
  ) -> Result<Vec<Fr>, String>
  ```
  * Input: the commitment
  * Input: a list of indices, for which we need to generate t_i
  * Input: Value: the messages that is committed to
  * Output: a list of field elements
  * Error: ciphersuite id not supported
  * Error: lengths do no match
  * Steps:
    1. `digest = SHA512(C | S | m[S])`
    2. for `0 <= i < set.len()`, `res[i] = hash_to_field_veccom(i, digest)`
