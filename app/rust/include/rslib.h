#pragma once

#include <stdint.h>

#include "parser_common.h"
#include "parser_txdef.h"

/****************************** others
 * ********************************************************************************/

// functions for testing sapling
void sapling_derive_dummy_ask_and_nsk(const uint8_t *seed_ptr, uint8_t *ask_out, uint8_t *nsk_out);

void rust_prf_expand(const uint8_t *seed_ptr, const uint8_t *t, uint8_t *expanded_out);

void rust_from_bytes_wide(uint8_t *dest, uint8_t *src);

void rust_fr_add(uint8_t *a, uint8_t *b, uint8_t *out);

void master_spending_key_zip32(uint8_t *seed, uint8_t *out_key);

void sapling_nsk_to_nk(uint8_t *nsk, uint8_t* out_nk);

void sapling_ask_to_ak(uint8_t *ask, uint8_t* out_ak);

void rust_blake2b_expand_vec_four(
    const uint8_t* in_a_ptr, size_t in_a_len,
    const uint8_t* in_b_ptr, size_t in_b_len,
    const uint8_t* in_c_ptr, size_t in_c_len,
    const uint8_t* in_d_ptr, size_t in_d_len,
    const uint8_t* in_e_ptr, size_t in_e_len,
    uint8_t* out_hash_ptr, size_t out_hash_len);

void rust_blake2b_expand_vec_three(
        const uint8_t* in_a_ptr, size_t in_a_len,
        const uint8_t* in_b_ptr, size_t in_b_len,
        const uint8_t* in_c_ptr, size_t in_c_len,
        const uint8_t* in_d_ptr, size_t in_d_len,
        uint8_t* out_hash_ptr, size_t out_hash_len);

void rust_blake2b_expand_vec_two(
        const uint8_t* in_sk_ptr, size_t in_sk_len,
        const uint8_t* in_b_ptr, size_t in_b_len,
        const uint8_t* in_c_ptr, size_t in_c_len,
        uint8_t* out_hash_ptr, size_t out_hash_len);


//ZIP32 functions
void get_pkd(const uint8_t *seed_ptr, const uint32_t pos, const uint8_t *diversifier_ptr, uint8_t *pkd);

void get_pkd_from_seed(const uint8_t *seed_ptr, const uint32_t pos, const uint8_t *start_index, uint8_t *diversifier_ptr, uint8_t *pkd);

void get_diversifier_list(const uint8_t *sk_ptr, uint8_t *diversifier_list);

void get_diversifier_fromlist(const uint8_t *diversifier_list, uint8_t *diversifier);

uint8_t is_valid_diversifier(const uint8_t *diversifier);

void get_diversifier_list_withstartindex(const uint8_t *seed_ptr, const uint32_t pos, const uint8_t *startindex, uint8_t *diversifier_list);

void get_default_diversifier_list_withstartindex(const uint8_t *seed_ptr, const uint32_t pos, uint8_t *startindex, uint8_t *diversifier_list);

void get_default_diversifier_without_start_index(const uint8_t *see_ptr, const uint32_t pos, uint8_t *default_diversifier);

void zip32_master(const uint8_t *seed_ptr, uint8_t *sk_ptr, uint8_t *dk_ptr);

void zip32_child_ask_nsk(const uint8_t *seed_ptr, uint8_t *ask, uint8_t *nsk, const uint32_t pos);

void zip32_nsk_from_seed(const uint8_t *seed_ptr, uint8_t *nsk);

void zip32_ivk(const uint8_t *ak_ptr, uint8_t *ivk_ptr, const uint32_t pos);

void zip32_ovk(const uint8_t *seed_ptr, uint8_t *ovk, const uint32_t pos);

void zip32_fvk(const uint8_t *seed_ptr, uint8_t *fvk, const uint32_t pos);

void zip32_child_proof_key(const uint8_t *seed_ptr, uint8_t *ak_ptr, uint8_t *nsk_ptr, const uint32_t pos);

//Rseed
void rseed_get_esk_epk(const uint8_t *seed_ptr, uint8_t *d_ptr, uint8_t *output_esk_ptr, uint8_t *output_epk_ptr);

void rseed_get_rcm(const uint8_t *input, uint8_t *output_ptr);

//Commitments
void compute_note_commitment(uint8_t *inputptr, const uint8_t *rcmptr,const uint64_t value,const uint8_t *diversifier_ptr, const uint8_t *pkd);

void compute_note_commitment_fullpoint(uint8_t *inputptr, const uint8_t *rcmptr,const uint64_t value, const uint8_t *diversifier_ptr, const uint8_t *pkd);

void compute_value_commitment(const uint64_t value, const uint8_t *rcmptr, uint8_t *output);

void compute_nullifier(uint8_t *ncmptr, uint64_t pos, const uint8_t *nsk_ptr, uint8_t *outputptr);

//Note encryption
void blake2b_prf(uint8_t *inputptr, uint8_t *outptr);

void ka_to_key(uint8_t *esk_ptr, uint8_t *pkd_ptr, uint8_t *epk_ptr, uint8_t *output_ptr);

void prepare_enccompact_input(uint8_t *d, uint64_t value, uint8_t *rcm, uint8_t memotype, uint8_t *output);

//RedJubjub
void random_fr(uint8_t *alpha_ptr);

void randomized_secret_from_seed(uint8_t *seed_ptr, uint32_t pos, uint8_t *alpha_ptr, uint8_t *output_ptr);

void get_rk(uint8_t *ask_ptr, uint8_t *alpha_ptr, uint8_t *output_ptr);
void rsk_to_rk(const uint8_t* rsk_ptr, uint8_t* rk_ptr);

void randomize_pk(uint8_t *alpha_ptr, uint8_t *pk_ptr);

void sign_redjubjub(uint8_t *key_ptr, uint8_t *msg_ptr, uint8_t *out_ptr);

//Session key
void sessionkey_agree(uint8_t *scalar_ptr, uint8_t *point_ptr, uint8_t *output_ptr);

void pubkey_gen(uint8_t *scalar_ptr, uint8_t *output_ptr);
