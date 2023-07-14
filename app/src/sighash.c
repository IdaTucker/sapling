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
}

void signature_hash(const uint8_t *txdata, uint8_t *start_signdata, uint16_t inputlen, const uint8_t tx_version, uint8_t *output){
}

static void signature_script_hash_v4(const uint8_t *input, uint16_t inputlen, uint8_t *script, uint16_t scriptlen, uint8_t *output) {
}

void signature_script_hash(const uint8_t *input, uint8_t *start_signdata, uint16_t inputlen, uint8_t *script, uint16_t scriptlen, uint8_t index, const uint8_t tx_version, uint8_t *output) {
}

