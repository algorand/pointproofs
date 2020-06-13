# Pairing based vector commitment Signature
<!---
This file is still under construction
--->


* Paper: https://eprint.iacr.org/2020/419
* Code: https://github.com/algorand/pointproofs/


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
  /// the PointproofsG1 and PointproofsG2 can be switched to improve verification speed
  /// PointproofsG1 represents G1 in the paper, and can be mapped to either bls12-381::G1 or bls12-381::G2
  type PointproofsG1 = G1;
  type PointproofsG2 = G2;
  type PointproofsG1Affine = G1Affine;
  type PointproofsG2Affine = G2Affine;
  ```

  Group switching can be enabled during compiling with a flag.
  By default, the groups are __NOT__ switched.

  ```
  features=group_switched
  ```


## ProverParam and VerifierParam

* Definitions
  ``` rust
  pub struct ProverParams {
      pub ciphersuite: Ciphersuite,
      pub n: usize,
      pub generators: Vec<PointproofsG1Affine>,
      pub pp_len: usize,
      pub precomp: Vec<PointproofsG1Affine>,
  }
  ```

  ``` rust
  pub struct VerifierParams {
      ciphersuite: Ciphersuite,
      pub n: usize,
      generators: Vec<PointproofsG2Affine>,
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
  * Input: vector length n
  * Output: prover parameter and verifier parameter
  * Error: ciphersuite is not supported
  * Error: seed is too short
  * Error: n is too large
  * Note: This function is only used for testing. For deployment, use `pointproofs_paramgen` trait for parameters.

  ``` rust
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>
  ```
  * Input: either a `ProverParams` or a `VerifierParam`
  * Input: a writable buffer
  * Input: a flag whether to compress the group point or not; must be true
  * Output: none
  * Error: compression is false
  * Error: ciphersuite is not supported
  * Error: serialization fails
  * Steps: serialize the parameters into a blob
    1. For `ProverParams`, convert `|ciphersuite id | n | generators | pp_len | [pre_compute] |` to bytes
    2. For `VerifierParam`, convert  `|ciphersuite id | n | generators | pp_len | [pre_compute] | gt_element` to bytes

  ``` rust
  fn deserialize<R: Read>(reader: &mut R, compressed: bool) -> Result<Self>
  ```
  * Input: a readeble buffer
  * Input: a flag whether the group elements are expected to be compressed or not; must be true
  * Output: either a `ProverParams` or a `VerifierParam`
  * Error: compression is false
  * Error: ciphersuite is not supported
  * Error: encoded buffer has a different compressness than specified
  * Error: deserialization fails
  * Steps: deserialize the blob into parameters
    1. For `ProverParams`, convert bytes to `|ciphersuite id | n | generators | pp_len | [pre_compute] |`
    2. For `VerifierParam`, convert bytes to `|ciphersuite id | n | generators | pp_len | [pre_compute] | gt_element`

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
  * Input: a flag whether to compress the group point or not; must be true
  * Output: none
  * Error: compression is false
  * Error: ciphersuite is not supported
  * Error: serialization fails
  * Steps: convert `| ciphersuite | commit |` to bytes


  ``` rust
  fn deserialize<R: Read>(reader: &mut R, compressed: bool) -> Result<Self>
  ```
  * Input: a readeble buffer
  * Input: a flag whether the group elements are expected to be compressed or not; must be true
  * Output: a `Commitment`
  * Error: compression is false  
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
  * Error: values.length does not match n
  * Steps:
    1. hash `value`s into `scalar`s
    2. `commit = \prod prover_params.generators[i]^scalar[i] for i in indices`

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
  * Error: self.ciphersuite does not match prover_params.ciphersuite
  * Error: index out of range
  * Steps:
    1. hash `value_before` into `old_scalar`
    2. hash `value_after` into `new_scalar`
    3. `commit = commit * prover_params,generators[changed_index]^(new_scalar-old_scalar)`

  ``` rust
  pub fn batch_update<Blob: AsRef<[u8]>>(
      &mut self,
      prover_params: &ProverParams,
      changed_index: &[usize],
      value_before: &[Blob],
      value_after: &[Blob],
  ) -> Result<(), String>
  ```
  * Input: self, a `Commitment`
  * Input: a `ProverParam`
  * Input: a list of `indices` to be updated
  * Input: a list of original values
  * Input: a list of values updated to
  * Output: mutate self to the updated commit
  * Error: ciphersuite is not supported
  * Error: self.ciphersuite does not match prover_params.ciphersuite
  * Error: index out of range
  * Error: # of changed_index, value_before or value_after do not match
  * Steps:
    1. for `i` in `indices`
      1. hash `value_before[i]`s into `old_scalar[i]`
      2. hash `value_after[i]`s into `new_scalar[i]`
      2. `commit = commit * \prod prover_params.generators[i]^(new_scalar[i]-old_scalar[i])` for i in indices

## Proofs

* Definitions

  ``` rust
  pub struct Proof {
      ciphersuite: Ciphersuite,
      proof: PointproofsG1,
  }
  ```

* Methods
  ``` rust
  /// generate a new proof
  pub fn new<Blob: AsRef<[u8]>>(
      prover_params: &ProverParams,
      values: &[Blob],
      index: usize,
  ) -> Result<Self, String>
  ```
  * Input: a `ProverParams`
  * Input: a list of values to commit
  * Input: the index for which the proof is generated
  * Output: a new proof
  * Error: ciphersuite is not supported
  * Error: index out of range
  * Error: values.length does not match n
  * Steps:
    1. hash the `value`s into `scarlar`s
    2. `proof = \prod prover_params.generators[n - index + i]^scalar[i]` for i in range(n) except index
    (_in implementation we implement it as `for i in range(n)` without exception, since the corresponding generator was already set to `0`_)


  ``` rust
  /// generate a list of new proofs
  pub fn batch_new<Blob: AsRef<[u8]>>(
      prover_params: &ProverParams,
      values: &[Blob],
      indices: &[usize],
  ) -> Result<Vec<Self>, String>
  ```
  * Input: a `ProverParam`
  * Input: a list of values to commit
  * Input: a list of indices for which the proofs are generated
  * Output: a list of proofs, each corresponding to an index
  * Error: ciphersuite is not supported
  * Error: index out of range
  * Error: values.length does not match n
  * Error: indices.length = 0 or indices.length > n
  * Steps:
    1. hash the `value`s into `scarlar`s
    2. for j in 0..indices.len():
        1. `proof[j] = \prod prover_params[n - indices[j] + i]^scalar[i]` for i in range(n) except index     
        (_in implementation we implement it as `for i in range(n)` without exception, since the corresponding generator was already set to `1`_)


  ``` rust
  /// generate a single, aggregated proof
  pub fn batch_new_aggregated<Blob: AsRef<[u8]>>(
      prover_params: &ProverParams,
      commit: &Commitment,
      values: &[Blob],
      indices: &[usize],
  ) -> Result<Self, String>
  ```
  * Input: a `ProverParam`
  * Input: a list of values to commit
  * Input: a list of indices for which the proofs are generated
  * Output: an aggregated proof for proofs, each corresponding to an index
  * Error: ciphersuite is not supported
  * Error: index out of range
  * Error: values.length does not match n
  * Error: indices.length = 0 or indices.length > n
    1. hash the `value`s into `scarlar`s
    2. `proof = 1`
    3. for j in 0..indices.len():
        1. `proof[j] = \prod prover_params[n - indices[j] + i]^scalar[i]` for i in range(n) except indices[j]
            (_in implementation we implement it as `for i in range(n)` without exception, since the corresponding generator was already set to `1`_)
        2. `proof *= proof[j]`

    More efficient implementation is via the following
    `\prod_k prover_params[k]^c[k]` where `c[k]=\sum scalar[k+i-n] * t_i` for i in indices (with scalars at out-of-range indices understood to be 0)

  ``` rust
  /// For updating your proof when someone else's value changes
  /// Not for updating your own proof when your value changes -- because then the proof does not change!
  pub fn update<Blob: AsRef<[u8]>>(
      &mut self,
      prover_params: &ProverParams,
      proof_index: usize,
      changed_index: usize,
      value_before: Blob,
      value_after: Blob,
  ) -> Result<(), String>
  ```
  * Input: self, the proof to be updated
  * Input: a `ProverParams`
  * Input: proof_index, the index for which the proof is generated
  * Input: changed_index, the index for which the proof will be updated
  * Output: mutate self to a new proof
  * Error: ciphersuite is not supported
  * Error: index out of range
  * Note: This function is used for updating your proof when someone else's value changes. It is not for updating your own proof when your value changes -- because then the proof does not change!
  * Steps:
    1. hash `value_before` into `old_scalar`
    2. hash `value_after` into `new_scalar`
    3. `proof = proof * prover_params.generators[changed_index + n - proof_index]^(new_scalar-old_scalar)`


  ``` rust
  /// Verify the proof
  pub fn verify<Blob: AsRef<[u8]>>(
      &self,
      verifier_params: &VerifierParams,
      com: &Commitment,
      value: Blob,
      index: usize,
  ) -> bool
  ```
  * Input: self, the proof to be verified
  * Input: a `VerifierParams`
  * Input: the commitment
  * Input: the value that proof is generated
  * Input: index of the value in the value vector
  * Output: if the proof is valid w.r.t. commit/values/index or not
  * Steps:
    1. Compute `t = hash_to_field_pointproofs(value)`
    2. return `e(com^{1/t}, veririer_params.generators[n-index-1]) * e(proof^{-1/t}, generator_of_g2) == gt_elt`

  ``` rust
  /// Aggregates a vector of proofs into a single one
  /// Note: the aggregator does not check the validity of
  /// individual commits. The caller may need to check them
  /// if they care for it.
  pub fn same_commit_aggregate<Blob: AsRef<[u8]>>(
      commit: &Commitment,
      proofs: &[Self],
      set: &[usize],
      value_sub_vector: &[Blob],
      n: usize,
  ) -> Result<Self, String>
  ```
  * Input: a commitment
  * Input: a list of proofs for this commitment
  * Input: the set of indices for proofs
  * Input: the set of values for proofs
  * Input: n - the public parameter
  * Output: an aggregated proof
  * Error: the lengths do not match
  * Error: ciphersuite not supported
  * Steps:
    1. if `commit.len() == 1`, return `proof[0]`
    2. hash to a list of scalars `ti = hash_to_ti(commit, set, value_sub_vector, n)`
    3. return `proof = \prod proofs[i]^ti[i]`

  ``` rust
  /// Aggregate an array of proofs, each is an (aggregated) proof for a
  /// commit, into a single proof
  pub fn cross_commit_aggregate_partial<Blob: AsRef<[u8]>>(
      commits: &[Commitment],
      proofs: &[Self],
      set: &[Vec<usize>],
      value_sub_vector: &[Vec<Blob>],
      n: usize,
  ) -> Result<Self, String>
  ```
  * Input: a vector commitments
  * Input: a vector of proofs, each (aggregate) proof belongs to a commitment
  * Input: a vector of sets of indices for proofs, each set of indices belongs to a same commitment
  * Input: a vector of sets of values for proofs, each set of values belongs to a same commitment
  * Output: an aggregated proof
  * Error: the lengths do not match
  * Error: ciphersuite not supported
  * Steps:
    1. if `commit.len() == 1`, return `aggregate(commits[0], proofs[0], set[0], value_sub_vector[0], n)`
    2. hash to a list of scalars `hash_to_tj(&commits, &set, &value_sub_vector, n)`
    3. return `proof = \prod proofs[i]^tj[i]`


  ``` rust
  /// Aggregate a 2-dim array of proofs, each row corresponding to a
  /// commit, into a single proof
  pub fn cross_commit_aggregate_full<Blob: AsRef<[u8]>>(
      commits: &[Commitment],
      proofs: &[Vec<Self>],
      set: &[Vec<usize>],
      value_sub_vector: &[Vec<Blob>],
      n: usize,
  ) -> Result<Self, String>
  ```
  * Input: a vector commitments
  * Input: a vector of vectors of proofs, each vector of proofs belongs to a same commitment
  * Input: a vector of sets of indices for proofs, each set of indices belongs to a same commitment
  * Input: a vector of sets of values for proofs, each set of values belongs to a same commitment
  * Output: an aggregated proof
  * Error: the lengths do not match
  * Error: ciphersuite not supported
  * Steps:
    1. if `commit.len() == 1`, return `aggregate(commits[0], proofs[0], set[0], value_sub_vector[0], n)`
    2. hash to a list of scalars `hash_to_tj(&commits, &set, &value_sub_vector, n)`
    3. for  `0<=i<commit.len` compute `pi[i] = aggregate(commits[i], proofs[i], set[i], value_sub_vector[i], n)`
    4. return `proof = \prod pi[i]^tj[i]`

  ``` rust
  /// batch verify a proof for a list of values/indices
  pub fn same_commit_batch_verify<Blob: AsRef<[u8]>>(
      &self,
      verifier_params: &VerifierParams,
      com: &Commitment,
      set: &[usize],
      value_sub_vector: &[Blob],
  ) -> bool
  ```
  * Input is similar to `aggregate`
  * Output: if the proof is valid w.r.t. the inputs or not
  * Formula: `e(com, g2^{tmp*\sum_{i \in set} \alpha^{N+1-i} t_i})* e(proof^{-tmp}, g2)?= e(g1, g2)^{alpha^N+1}` where `tmp = 1/\sum value_i*t_i`
  * Steps:
    1. if `set.len() == 1`, return `self.verify(&verifier_params, &com, value_sub_vector[0].as_ref(), set[0]);`
    2. Set `t_i = hash_to_ti(com, set, value_sub_vector, verifier_params.n)`
    3. Compute `tmp = 1/ \sum value_i*t_i`
    4. Return `e(com, (\Prod verifier_params.generators[n-i-1]^(tmp * t_i)) * e(proof^{-tmp}, g2) == gt_elt`

  ``` rust
  /// verify a proof which was aggregated from 2-dim array of proofs
  pub fn cross_commit_batch_verify<Blob: AsRef<[u8]>>(
      &self,
      verifier_params: &VerifierParams,
      com: &[Commitment],
      set: &[Vec<usize>],
      value_sub_vector: &[Vec<Blob>],
  ) -> bool
  ```
  * Input is similar to `cross_commit_aggregate`
  * Output: if the proof is valid w.r.t. the inputs or not
  * Formula: `\prod e(com[j], g2^{\sum alpha^{n + 1 - i} * t_j,i * tj * tmp} ) * e(proof^{-tmp}, g2) == e(g1, g2)^{alpha^{n+1}}`
  where `tmp = 1/\sum m_j,i * t_j,i * tj`
  * Steps:
    1. if `com.len() == 1`, return `self.batch_verify(&verifier_params, &com[0], &set[0], &value_sub_vector[0])`
    2. compute `tmp = 1 / sum_j tj (sum_i m_j,i * t_j,i)`
    3. formulate `g1_vec = [com | (1/proof)^tmp]`
    4. set `g2_vec` as for `j \in [num_commit], (\Prod for i in set[j] of verifier_params.generators[n-i-1]^(tmp * t_j,i * t_j))`,
    5. `g2_vec.push(G2::one())`
    6. return `pairing_multi_product(g1_vec, g2_vec) == verifier_params.gt_elt`



  ``` rust
  fn serialize<W: Write>(&self, writer: &mut W, compressed: bool) -> Result<()>
  ```
  * Input: a `Commitment`
  * Input: a writable buffer
  * Input: a flag whether to compress the group point or not; must be true
  * Output: none
  * Error: compression is false  
  * Error: ciphersuite is not supported
  * Error: serialization fails
  * Steps: convert `| ciphersuite | proof |` to bytes


  ``` rust
  fn deserialize<R: Read>(reader: &mut R, compressed: bool) -> Result<Self>
  ```
  * Input: a readeble buffer
  * Input: a flag whether the group elements are expected to be compressed or not; must be true  
  * Output: a `Commitment`
  * Error: compression is false  
  * Error: ciphersuite is not supported
  * Error: encoded buffer has a different compressness than specified
  * Error: deserialization fails
  * Steps: convert bytes to `| ciphersuite | proof |`

## hashes

* pointproofs' hash to field

  ``` rust
  // hash_to_field_pointproofs use SHA 512 to hash a blob into a non-zero field element
  pub fn hash_to_field_pointproofs<Blob: AsRef<[u8]>>(input: Blob) -> Fr
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
    3. for `0 <= i < commits.len()`, `res[i] = hash_to_field_pointproofs(i, digest)`
  * Note: this procedure is a bit different from the paper, where no intermediate
  digest is generated. We pre-hash the data into a digest to improve efficiency.

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
    2. for `0 <= i < set.len()`, `res[i] = hash_to_field_pointproofs(i, digest)`
  * Note: this procedure is a bit different from the paper, where no intermediate
  digest is generated. We pre-hash the data into a digest to improve efficiency.


## Difference from the paper

Here are a list of minor difference of the spec from the paper.
Those differences are either to improve the performance or simplicity
of code. They have no impact on the security of the scheme.

* hash to ti-s and tj-s:
  * in the code we hash the inputs into a digest first,
and then use this digest (concatenated with an index) to generate a field
element.
  * in the paper, there is no intermediate digest. the input is concatenated
  with the index to generated a field element.

* indexing:
  * in the code, the indices start from 0 and end with n-1
  * in the paper, the indices start from 1 and end with n
