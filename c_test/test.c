#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "pointproofs_c.h"


//#define GROUP_SWITCHED

// #define DEBUG

// Credit: https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
void hexDump (const char *desc, const void *addr, const int len);

// very simple and basic tests for commit/prove/(de)serializations
int test_basic() {
  size_t n = 1028;
  size_t k = n-8; // For more flexible `n` val. 
  size_t u_index = k + 1;
  size_t u_index_new = k ;

  // values to commit
  int counter = 0;
  pointproofs_value values[n];
  for (counter = 0; counter < n; counter++) {
    char * tmp = (char*) malloc(64 * sizeof(char));
    sprintf(tmp, "This is message %d for commit %d!", counter, 0);
    values[counter].data = (const unsigned char*) tmp;
    values[counter].len = strlen(tmp);
  }

#ifdef DEBUG
  printf("values:\n");
  for (counter = 0; counter < n; counter++) {
    printf("%zu: %s\n", values[counter].len, values[counter].data);
  }
#endif

  // generate parameters
  char seed[] = "this is a very long seed for pointproofs tests";
  uint8_t ciphersuite = 0;

  pointproofs_params pointproofs_param;
  assert(pointproofs_paramgen((const uint8_t*) seed, sizeof(seed), ciphersuite, n, &pointproofs_param) == 0);

  // testing (de)serialization of parameters
  pointproofs_pp_bytes pointproofs_pp_string;
  pointproofs_vp_bytes pointproofs_vp_string;
  pointproofs_pp pp_recover;
  pointproofs_vp vp_recover;
  pointproofs_pp_bytes pointproofs_pp_string_recover;
  pointproofs_vp_bytes pointproofs_vp_string_recover;

  assert(pointproofs_pp_serial(pointproofs_param.prover, &pointproofs_pp_string) == 0);
  assert(pointproofs_vp_serial(pointproofs_param.verifier, &pointproofs_vp_string) == 0);
  assert(pointproofs_pp_deserial(pointproofs_pp_string, &pp_recover) == 0);
  assert(pointproofs_vp_deserial(pointproofs_vp_string, &vp_recover) == 0);
  assert(pointproofs_pp_serial(pp_recover, &pointproofs_pp_string_recover) == 0);
  assert(pointproofs_vp_serial(vp_recover, &pointproofs_vp_string_recover) == 0);

#ifdef DEBUG
  hexDump("prover param (in bytes)", pointproofs_pp_string.data, pointproofs_pp_string.len);
  hexDump("prover param recovered (in bytes)", pointproofs_pp_string_recover.data, pointproofs_pp_string_recover.len);

  hexDump("verifier param (in bytes)", pointproofs_vp_string.data, pointproofs_vp_string.len);
  hexDump("verifier param recovered (in bytes)", pointproofs_vp_string_recover.data, pointproofs_vp_string_recover.len);
#endif

  assert(memcmp(pointproofs_pp_string.data, pointproofs_pp_string_recover.data, pointproofs_pp_string.len) == 0);
  assert(memcmp(pointproofs_vp_string.data, pointproofs_vp_string_recover.data, pointproofs_vp_string.len) == 0);

  // generate a commit
  pointproofs_commitment commit;
  pointproofs_commitment_bytes commit_string;
  pointproofs_commitment commit_recover;
  pointproofs_commitment_bytes commit_string_recover;

  assert(pointproofs_commit(pp_recover, values, n, &commit) == 0);
  assert(pointproofs_commit_serial(commit, &commit_string) == 0);
  assert(pointproofs_commit_deserial(commit_string, &commit_recover) == 0);
  assert(pointproofs_commit_serial(commit_recover, &commit_string_recover) == 0);

#ifdef DEBUG
  hexDump("commit (in bytes)", commit_string.data, commit_string.len);
  hexDump("commit recovered (in bytes)", commit_string_recover.data, commit_string_recover.len);
#endif

  assert(strcmp((const char*) commit_string.data, (const char*) commit_string_recover.data) == 0);

  pointproofs_proof proof;
  pointproofs_proof_bytes proof_string;
  pointproofs_proof proof_recover;
  pointproofs_proof_bytes proof_string_recover;

  for (counter = 0; counter < k; counter++) {
    // generate a proof
    assert(pointproofs_prove(pp_recover, values, n, counter, &proof) == 0);
    assert(pointproofs_proof_serial(proof, &proof_string) == 0);
    assert(pointproofs_proof_deserial(proof_string, &proof_recover) == 0);
    assert(pointproofs_proof_serial(proof_recover, &proof_string_recover) == 0);

#ifdef DEBUG
    hexDump("proof (in bytes)", proof_string.data, proof_string.len);
    hexDump("proof recovered (in bytes)", proof_string_recover.data, proof_string_recover.len);
#endif

    assert(strcmp((const char*) proof_string.data, (const char*) proof_string_recover.data) == 0);

    // verify the proof
    assert(pointproofs_verify(vp_recover, commit, proof, values[counter], counter) == true);
  }

  // update the commitment for index = 33
  pointproofs_commitment new_commit;
  pointproofs_proof new_proof;
  assert(pointproofs_commit_update(pp_recover, commit, u_index, values[u_index], values[u_index_new], &new_commit) == 0);
  for (counter = 0; counter < k; counter++) {
    // update the proofs; the updated index will be 33
    assert(pointproofs_prove(pp_recover, values, n, counter, &proof) == 0);
    assert(pointproofs_proof_update(pp_recover, proof, counter, u_index, values[u_index], values[u_index_new], &new_proof) == 0);
    // verify the new proof
    assert(pointproofs_verify(vp_recover, new_commit, new_proof, values[counter], counter) == true);
  }

  pointproofs_free_commit(commit);
  pointproofs_free_commit(commit_recover);
  pointproofs_free_commit(new_commit);
  pointproofs_free_proof(proof);
  pointproofs_free_proof(proof_recover);
  pointproofs_free_proof(new_proof);
  pointproofs_free_prover_params(pointproofs_param.prover);
  pointproofs_free_prover_params(pp_recover);
  pointproofs_free_verifier_params(pointproofs_param.verifier);
  pointproofs_free_verifier_params(vp_recover);

  pointproofs_free_pp_string(pointproofs_pp_string); //need to free.
  pointproofs_free_pp_string(pointproofs_pp_string_recover); //need to free.
  pointproofs_free_vp_string(pointproofs_vp_string); //need to free.
  pointproofs_free_vp_string(pointproofs_vp_string_recover); //need to free.
  pointproofs_free_commit_string(commit_string); //need to free.
  pointproofs_free_commit_string(commit_string_recover); //need to free.
  pointproofs_free_proof_string(proof_string); //need to free.
  pointproofs_free_proof_string(proof_string_recover); //need to free.


  printf("basis tests: success\n");
  return 0;
}



// same commit aggregation and batch verification tests
int test_same_commit_aggregation() {
  size_t n = 1024;

  // values to commit
  int counter = 0;
  pointproofs_value values[n];
  for (counter = 0; counter < n; counter++) {
    char * tmp = (char*) malloc(64 * sizeof(char));
    sprintf(tmp, "This is message %d for commit %d!", counter, 0);
    values[counter].data = (const unsigned char*) tmp;
    values[counter].len = strlen(tmp);
  }

#ifdef DEBUG
  printf("values:\n");
  for (counter = 0; counter < 20; counter++) {
    printf("%zu: %s\n", values[counter].len, values[counter].data);
  }
#endif

  // generate parameters
  char seed[] = "this is a very long seed for pointproofs tests";
  uint8_t ciphersuite = 0;

  pointproofs_params pointproofs_param;
  assert(pointproofs_paramgen((const uint8_t*) seed, sizeof(seed), ciphersuite, n, &pointproofs_param) == 0);
  pointproofs_pp pp = pointproofs_param.prover;
  pointproofs_vp vp = pointproofs_param.verifier;

  pointproofs_commitment commit;
  pointproofs_proof proof[32];
  size_t index[32];
  pointproofs_value sub_values[32];

  // generate a commit and 32 proofs
  assert(pointproofs_commit(pp, values, n, &commit) == 0);
  for (counter = 0; counter < 32; counter++) {
    // generate a proof
    assert(pointproofs_prove(pp, values, n, counter, &proof[counter]) == 0);
    index[counter] = counter;
    sub_values[counter] = values[counter];

    // verify the proof
    assert(pointproofs_verify(vp, commit, proof[counter], values[counter], counter) == true);
  }

  // aggregate
  pointproofs_proof agg_proof;
  assert(pointproofs_same_commit_aggregate(commit, proof, index, sub_values, 32, n, &agg_proof) == 0);

  // verify the proof
  assert(pointproofs_same_commit_batch_verify(vp, commit, agg_proof, index, sub_values, 32) == true);

  pointproofs_free_prover_params(pointproofs_param.prover);
  pointproofs_free_verifier_params(pointproofs_param.verifier);
  pointproofs_free_proof(agg_proof);
  pointproofs_free_commit(commit);
  for (counter = 0; counter < 32; counter++)
  {
    pointproofs_free_proof(proof[counter]);
    free((void*)values[counter].data);
  }
  printf("aggregation tests: success\n");
  return 0;
}



// across commits aggregation and batch verification tests
int test_x_commit_aggregation() {
  size_t n = 1024;
  size_t k = 32;
  size_t commit_indices[32];
  int i;
  int total = 0;
  for (i = 0; i < 32; i++) {
    commit_indices[i] = i + 2;
    total += commit_indices[i];
  }

  // values to commit
  int counter = 0;
  int com_counter = 0;
  pointproofs_value values[k][n];
  for (com_counter = 0; com_counter < k; com_counter++) {
    for (counter = 0; counter < n; counter++) {
      char* tmp = (char*) malloc(64 * sizeof(char));
      sprintf(tmp, "This is message %d for commit %d!", counter, com_counter);
      values[com_counter][counter].data = (const unsigned char*) tmp;
      values[com_counter][counter].len = strlen(tmp);
    }
  }

#ifdef DEBUG
  printf("values:\n");
  for (com_counter = 0; com_counter < k; com_counter++) {
    for (counter = 0; counter < commit_indices[com_counter]; counter++) {
      printf("%zu: %s\n", values[com_counter][counter].len, values[com_counter][counter].data);
    }
  }
#endif

  // generate parameters
  char seed[] = "this is a very long seed for pointproofs tests";
  uint8_t ciphersuite = 0;

  pointproofs_params pointproofs_param;
  assert(pointproofs_paramgen((const uint8_t*) seed, sizeof(seed), ciphersuite, n, &pointproofs_param) == 0);
  pointproofs_pp pp = pointproofs_param.prover;
  pointproofs_vp vp = pointproofs_param.verifier;

  // generate 32 commit and 32*32 proofs
  pointproofs_commitment commit[32];
  for (com_counter = 0; com_counter < k; com_counter++) {
    assert(pointproofs_commit(pp, values[com_counter], n, &commit[com_counter]) == 0);
  }

  pointproofs_proof proof[total];
  pointproofs_proof same_commit_agg_proof[k];
  size_t index[total];
  pointproofs_value sub_values[total];

  i = 0;
  for (com_counter = 0; com_counter < k; com_counter++) {
    int cur_index = i;
    for (counter = 0; counter < commit_indices[com_counter]; counter++) {
      // generate a proof
      assert(pointproofs_prove(pp, values[com_counter], n, counter, &proof[i]) == 0);
      index[i] = counter;
      sub_values[i] = values[com_counter][counter];

      // verify the proof
      assert(pointproofs_verify(vp, commit[com_counter], proof[i], sub_values[i], counter) == true);

      i++;
    }
    assert(pointproofs_same_commit_aggregate(
      commit[com_counter],
      proof + cur_index,
      index + cur_index,
      sub_values + cur_index,
      commit_indices[com_counter],
      n, &same_commit_agg_proof[com_counter]) == 0);

    assert(pointproofs_same_commit_batch_verify(
      vp,
      commit[com_counter],
      same_commit_agg_proof[com_counter],
      index + cur_index,
      sub_values + cur_index,
      commit_indices[com_counter]) == true);
  }

  // test aggregation
  pointproofs_proof agg_proof1, agg_proof2;
  pointproofs_proof_bytes proof_string1, proof_string2;

  // aggregate full
  assert(pointproofs_x_commit_aggregate_full(commit, proof, index, sub_values, commit_indices, 32, n, &agg_proof1) == 0);
  // aggregate partial
  assert(pointproofs_x_commit_aggregate_partial(commit, same_commit_agg_proof, index, sub_values, commit_indices, 32, n, &agg_proof2) == 0);

  assert(pointproofs_proof_serial(agg_proof1, &proof_string1) == 0);
  assert(pointproofs_proof_serial(agg_proof2, &proof_string2) == 0);
  assert(strcmp((const char*) proof_string1.data, (const char*) proof_string2.data) == 0);

  // verify the proof
  assert(pointproofs_x_commit_batch_verify(vp, commit, agg_proof1, index, sub_values, commit_indices, 32) == true);


  // clear memory
  pointproofs_free_prover_params(pointproofs_param.prover);
  pointproofs_free_verifier_params(pointproofs_param.verifier);

  for (com_counter = 0; com_counter < k; com_counter++)
    pointproofs_free_commit(commit[com_counter]);

  pointproofs_free_proof(agg_proof1);
  pointproofs_free_proof(agg_proof2);
  for (com_counter = 0; com_counter < k; com_counter++)
    pointproofs_free_proof(same_commit_agg_proof[com_counter]);
  for (i = 0; i < total; i++)
    pointproofs_free_proof(proof[i]);

  for (com_counter = 0; com_counter < k; com_counter++) {
    for (counter = 0; counter < n; counter++) {
      free((void*) values[com_counter][counter].data);
    }
  }

  printf("aggregation tests: success\n");
  return 0;
}


int main(){

  test_basic();
  test_same_commit_aggregation();
  test_x_commit_aggregation();

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
