#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "veccom_c.h"

// #define DEBUG

// Credit: https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
void hexDump (const char *desc, const void *addr, const int len);

// very simple and basic tests for commit/prove/(de)serializations
int test_basic()
{
  size_t n = 1024;

  // values to commit
  int counter = 0;
  vcp_value values[n];
  for (counter =0;counter < n; counter ++) {
    char *tmp = (char*)malloc(64 * sizeof(char));
    sprintf(tmp, "This is message %d for commit %d!", counter, 0);
    values[counter].data = (const unsigned char *)tmp;
    values[counter].len = strlen(tmp);
  }

  #ifdef DEBUG
  printf("values:\n");
  for (counter =0;counter < 20; counter ++) {
    printf("%zu: %s\n", values[counter].len, values[counter].data);
  }
  #endif

  // generate parameters
  char seed[] = "this is a very long seed for pixel tests";
  char rngseed[] = "";
  char msg[] = "this is the message we want pixel to sign";
  uint8_t ciphersuite = 0;


  vcp_params    vcp_param     = vcp_paramgen((const uint8_t *)seed, sizeof(seed), ciphersuite, n);

  // testing (de)serialization of parameters
  vcp_pp_bytes  vcp_pp_string = vcp_pp_serial(vcp_param.prover);
  vcp_vp_bytes  vcp_vp_string = vcp_vp_serial(vcp_param.verifier);
  vcp_pp        pp_recover    = vcp_pp_deserial(vcp_pp_string);
  vcp_vp        vp_recover    = vcp_vp_deserial(vcp_vp_string);
  vcp_pp_bytes  vcp_pp_string_recover = vcp_pp_serial(pp_recover);
  vcp_vp_bytes  vcp_vp_string_recover = vcp_vp_serial(vp_recover);

  #ifdef DEBUG
  hexDump("prover param (in bytes)", vcp_pp_string.data, 256);
  hexDump("prover param recovered (in bytes)", vcp_pp_string_recover.data, 256);

  hexDump("verifier param (in bytes)", vcp_vp_string.data, 256);
  hexDump("verifier param recovered (in bytes)", vcp_vp_string_recover.data, 256);
  #endif

  assert( memcmp(vcp_pp_string.data, vcp_pp_string_recover.data, RAW_PP_LEN) == 0);
  assert( memcmp(vcp_vp_string.data, vcp_vp_string_recover.data, VP_LEN) == 0);


  // generate a commit
  vcp_commitment        commit                = vcp_commit(pp_recover, values, n);
  vcp_commitment_bytes  commit_string         = vcp_commit_serial(commit);
  vcp_commitment        commit_recover        = vcp_commit_deserial(commit_string);
  vcp_commitment_bytes  commit_string_recover = vcp_commit_serial(commit_recover);

  #ifdef DEBUG
  hexDump("commit (in bytes)", commit_string.data, COMMIT_LEN);
  hexDump("commit recovered (in bytes)", commit_string_recover.data, COMMIT_LEN);
  #endif

  assert( strcmp((const char *)commit_string.data, (const char *)commit_string_recover.data)==0);

  for (counter = 0; counter < 32; counter ++)
  {
    // generate a proof
    vcp_proof        proof                = vcp_prove(pp_recover, values, n, counter);
    vcp_proof_bytes  proof_string         = vcp_proof_serial(proof);
    vcp_proof        proof_recover        = vcp_proof_deserial(proof_string);
    vcp_proof_bytes  proof_string_recover = vcp_proof_serial(proof_recover);

    #ifdef DEBUG
    hexDump("proof (in bytes)", proof_string.data, PROOF_LEN);
    hexDump("proof recovered (in bytes)", proof_string_recover.data, PROOF_LEN);
    #endif

    assert( strcmp((const char *)proof_string.data, (const char *)proof_string_recover.data)==0);

    // verify the proof
    assert( vcp_verify(vp_recover, commit, proof, values[counter], counter) == true);
    vcp_free_proof(proof);
    vcp_free_proof(proof_recover);
  }

  // update the commitment for index = 33
  vcp_commitment  new_commit  = vcp_commit_update(pp_recover, commit, 33, values[33], values[44]);
  for (counter = 0; counter < 32; counter ++)
  {
    // update the proofs; the updated index will be 33
    vcp_proof proof     = vcp_prove(pp_recover, values, n, counter);
    vcp_proof new_proof = vcp_proof_update(pp_recover, proof, counter, 33, values[33], values[44]);
    // verify the new proof
    assert( vcp_verify(vp_recover, new_commit, new_proof, values[counter], counter) == true);
    vcp_free_proof(proof);
    vcp_free_proof(new_proof);
  }

  vcp_free_commit(commit);
  vcp_free_commit(commit_recover);
  vcp_free_commit(new_commit);

  vcp_free_prover_params(vcp_param.prover);
  vcp_free_prover_params(pp_recover);
  vcp_free_verifier_params(vcp_param.verifier);
  vcp_free_verifier_params(vp_recover);

  printf("basis tests: success\n");
  return 0;
}



// aggregation and batch verification tests
int test_aggregation()
{
  size_t n = 1024;

  // values to commit
  int counter = 0;
  vcp_value values[n];
  for (counter =0;counter < n; counter ++) {
    char *tmp = (char*)malloc(64 * sizeof(char));
    sprintf(tmp, "This is message %d for commit %d!", counter, 0);
    values[counter].data = (const unsigned char *)tmp;
    values[counter].len = strlen(tmp);
  }

  #ifdef DEBUG
  printf("values:\n");
  for (counter =0;counter < 20; counter ++) {
    printf("%zu: %s\n", values[counter].len, values[counter].data);
  }
  #endif

  // generate parameters
  char seed[] = "this is a very long seed for pixel tests";
  char rngseed[] = "";
  char msg[] = "this is the message we want pixel to sign";
  uint8_t ciphersuite = 0;


  vcp_params  vcp_param = vcp_paramgen((const uint8_t *)seed, sizeof(seed), ciphersuite, n);
  vcp_pp      pp        = vcp_param.prover;
  vcp_vp      vp        = vcp_param.verifier;

  // generate a commit and 32 proofs
  vcp_commitment  commit  = vcp_commit(pp, values, n);
  vcp_proof       proof[32];
  size_t          index[32];
  vcp_value       sub_values[32];
  for (counter = 0; counter < 32; counter ++)
  {
    // generate a proof
    proof[counter]      = vcp_prove(pp, values, n, counter);
    index[counter]      = counter;
    sub_values[counter] = values[counter];

    // verify the proof
    assert( vcp_verify(vp, commit, proof[counter], values[counter], counter) == true);
  }

  // aggregate
  vcp_proof agg_proof = vcp_same_commit_aggregate(commit, proof, index, sub_values, 32, n);

  // verify the proof
  assert( vcp_same_commit_batch_verify(vp, commit, agg_proof, index, sub_values, 32) == true);

  printf("aggregation tests: success\n");
  return 0;
}


int main(){


  test_aggregation();
//  test_basic();
  printf("Hello Algorand\n");
}



// Credit: https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
void hexDump (const char *desc, const void *addr, const int len) {
    int i;
    unsigned char buff[17];
    const unsigned char *pc = (const unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}
