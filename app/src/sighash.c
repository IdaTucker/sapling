/*******************************************************************************
*   (c) 2018 -2022 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include <inttypes.h>
#include <zxmacros.h>
#include <zxformat.h>
#include "os.h"
#include "cx.h"
#include "nvdata.h"
#include "sighash.h"
#include "index_sapling.h"
#include "txid.h"

#define  ZCASH_PREVOUTS_HASH_PERSONALIZATION "MASP_PrevoutHash"
#define  ZCASH_SEQUENCE_HASH_PERSONALIZATION "MASP_SequencHash"
#define  ZCASH_OUTPUTS_HASH_PERSONALIZATION "MASP_OutputsHash"
#define CTX_ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION "MASP_SSpendsHash"
#define CTX_ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION "MASP_SOutputHash"

//
const uint8_t CONSENSUS_BRANCH_ID_SAPLING[4] = {0xBB, 0x09, 0xB8, 0x76};       // sapling
const uint8_t CONSENSUS_BRANCH_ID_ORCHARD[4] = {0xB4, 0xD0, 0xD6, 0xC2};       // orchard

void sapling_transparent_prevouts_hash(const uint8_t *input, uint8_t *output) {

}

void sapling_transparent_sequence_hash(const uint8_t *input, uint8_t *output) {

}

void v4_transparent_outputs_hash(uint8_t *output) {
}


void shielded_output_hash(const uint8_t *input, uint16_t inputlen, uint8_t *output) {

}

void shielded_spend_hash(const uint8_t *input, uint16_t inputlen, uint8_t *output) {

}

static void signature_hash_v4(const uint8_t *input, uint16_t inputlen, uint8_t *output) {

}

static void signature_hash_v5(const uint8_t *input, uint8_t *start_signdata, uint8_t index, signable_input type, uint8_t *output) {
    cx_blake2b_t ctx;

    uint8_t personalization[16] = {0};
    MEMCPY(personalization, "MASP_TxHash_", 12);
    MEMCPY(personalization + 12, CONSENSUS_BRANCH_ID_ORCHARD, 4);
    cx_blake2b_init2(&ctx, 256, NULL, 0, (uint8_t *) personalization, 16);

    uint8_t header_digest[32] = {0};
    uint8_t transparent_digest[32] = {0};
    uint8_t sapling_digest[32] = {0};
    uint8_t orchard_digest[32] = {0};

    hash_header_txid_data(start_signdata, header_digest);
    transparent_sig_digest(input, start_signdata, index, type, transparent_digest);
    hash_sapling_txid_data(start_signdata, sapling_digest);
    hash_empty_orchard_txid_data(orchard_digest);

    cx_hash(&ctx.header, 0, header_digest, HASH_SIZE, NULL, 0);
    cx_hash(&ctx.header, 0, transparent_digest, HASH_SIZE, NULL, 0);
    cx_hash(&ctx.header, 0, sapling_digest, HASH_SIZE, NULL, 0);
    cx_hash(&ctx.header, CX_LAST, orchard_digest, HASH_SIZE, output, HASH_SIZE);
}

void signature_hash(const uint8_t *txdata, uint8_t *start_signdata, uint16_t inputlen, const uint8_t tx_version, uint8_t *output){
    if (tx_version == TX_VERSION_SAPLING) {
        signature_hash_v4(start_signdata, inputlen, output);
    }
    else if (tx_version == TX_VERSION_NU5)
    {
        signature_hash_v5(txdata, start_signdata, 0, shielded, output);
    }
}

static void signature_script_hash_v4(const uint8_t *input, uint16_t inputlen, uint8_t *script, uint16_t scriptlen, uint8_t *output) {
    cx_blake2b_t ctx;

	uint8_t personalization[16] = {0};
    MEMCPY(personalization, "MASP_SigHash", 12);
    MEMCPY(personalization + 12, CONSENSUS_BRANCH_ID_ORCHARD, 4);

    cx_blake2b_init2(&ctx, 256, NULL, 0, (uint8_t *) personalization, 16);
    cx_hash(&ctx.header, 0, input, inputlen, NULL, 0);

    cx_hash(&ctx.header, CX_LAST, script, scriptlen, output, HASH_SIZE);
}

void signature_script_hash(const uint8_t *input, uint8_t *start_signdata, uint16_t inputlen, uint8_t *script, uint16_t scriptlen, uint8_t index, const uint8_t tx_version, uint8_t *output) {
    if (tx_version==TX_VERSION_SAPLING) {
        signature_script_hash_v4(start_signdata, inputlen, script, scriptlen, output);
    }
    else if (tx_version == TX_VERSION_NU5)
    {
        signature_hash_v5(input, start_signdata, index, transparent, output);
    }
}

