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

#include <stdio.h>
#include <zxmacros.h>
#include <zxformat.h>
#include "app_mode.h"
#include "parser.h"
#include "parser_impl.h"
#include "parser_common.h"

#include "coin.h"
#include "parser_txdef.h"
#include "rslib.h"
#include "nvdata.h"
#include "bech32.h"
#include "base58.h"
#include "view.h"
#include <os_io_seproxyhal.h>

#define DEFAULT_MEMOTYPE        0xf6

typedef enum {
    type_tin = 0,
    type_tout = 1,
    type_sspend = 2,
    type_sout = 3,
    type_txfee = 4,
} sapling_parser_type_e;

typedef struct {
    sapling_parser_type_e type;
    uint8_t index;
} parser_sapling_t;

parser_error_t parser_sapling_path_with_div(const uint8_t *data, size_t dataLen, parser_addr_div_t *prs) {
    if (dataLen < 15) {
        return parser_context_unexpected_size;
    }
    parser_context_t pars_ctx;
    parser_error_t pars_err;
    pars_ctx.offset = 0;
    pars_ctx.buffer = data;
    pars_ctx.bufferLen = 4;
    uint32_t p = 0;
    pars_err = _readUInt32(&pars_ctx, &p);
    if (pars_err != parser_ok) {
        return pars_err;
    }
    prs->path = p | 0x80000000;
    memcpy(prs->div, data + 4, 11);
    return parser_ok;
}

parser_error_t parser_sapling_path(const uint8_t *data, size_t dataLen, uint32_t *p) {
    if (dataLen < 4) {
        return parser_context_unexpected_size;
    }
    parser_context_t pars_ctx;
    parser_error_t pars_err;
    pars_ctx.offset = 0;
    pars_ctx.buffer = data;
    pars_ctx.bufferLen = 4;
    pars_err = _readUInt32(&pars_ctx, p);
    if (pars_err != parser_ok) {
        return pars_err;
    }
    *p |= 0x80000000;
    return parser_ok;
}

void view_tx_state() {
    return;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))



    return parser_ok;
}

parser_error_t parser_validate() {
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(&numItems))

    char tmpKey[30];
    char tmpVal[30];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem( idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_sapling_display_value(uint64_t value, char *outVal,
                                            uint16_t outValLen, uint8_t pageIdx,
                                            uint8_t *pageCount) {
    char tmpBuffer[100];
    fpuint64_to_str(tmpBuffer, sizeof(tmpBuffer), value, 8);
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_sapling_display_address_t(const uint8_t *addr, char *outVal,
                                                uint16_t outValLen, uint8_t pageIdx,
                                                uint8_t *pageCount) {
    MEMZERO(outVal, outValLen);

    uint8_t address[VERSION_SIZE + CX_RIPEMD160_SIZE + CX_SHA256_SIZE];
    address[0] = VERSION_P2PKH >> 8;
    address[1] = VERSION_P2PKH & 0xFF;
    MEMCPY(address + VERSION_SIZE, addr + 4, CX_RIPEMD160_SIZE);

    cx_hash_sha256(address,
                   VERSION_SIZE + CX_RIPEMD160_SIZE,
                   address + VERSION_SIZE + CX_RIPEMD160_SIZE,
                   CX_SHA256_SIZE);

    cx_hash_sha256(address + VERSION_SIZE + CX_RIPEMD160_SIZE, CX_SHA256_SIZE,
                   address + VERSION_SIZE + CX_RIPEMD160_SIZE, CX_SHA256_SIZE);

    uint8_t tmpBuffer[60];
    size_t outLen = sizeof(tmpBuffer);

    int err = encode_base58(address, VERSION_SIZE + CX_RIPEMD160_SIZE + CHECKSUM_SIZE, tmpBuffer, &outLen);
    if (err != 0) {
        return parser_unexpected_error;
    }

    pageString(outVal, outValLen, (char *) tmpBuffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_sapling_display_address_s(uint8_t *div, uint8_t *pkd, char *outVal,
                                                uint16_t outValLen, uint8_t pageIdx,
                                                uint8_t *pageCount) {

    uint8_t address[DIV_SIZE + PKD_SIZE];
    MEMCPY(address, div, DIV_SIZE);
    MEMCPY(address + DIV_SIZE, pkd, PKD_SIZE);
    char tmpBuffer[100];
    bech32EncodeFromBytes(tmpBuffer, sizeof(tmpBuffer),
                          BECH32_HRP,
                          address,
                          sizeof(address),
                          1, BECH32_ENCODING_BECH32);
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
    return parser_ok;
}


parser_error_t parser_getNumItems(uint8_t *num_items) {
    return parser_ok;
}

parser_error_t parser_getItem(uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    return parser_ok;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        // General errors
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_display_idx_out_of_range:
            return "display_idx_out_of_range";
        case parser_display_page_out_of_range:
            return "display_page_out_of_range";
        case parser_unexpected_error:
            return "Unexpected internal error";
        case parser_no_memory_for_state:
            return "No enough memory for parser state";
            /////////// Context specific
        case parser_context_mismatch:
            return "context prefix is invalid";
        case parser_context_unexpected_size:
            return "context unexpected size";
        case parser_context_invalid_chars:
            return "context invalid chars";
            // Required fields error
            // Coin specific
        case parser_invalid_output_script:
            return "Invalid output script";
        case parser_unexpected_type:
            return "Unexpected data type";
        case parser_unexpected_method:
            return "Unexpected method";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_unexpected_number_items:
            return "Unexpected number of items";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_invalid_address:
            return "Invalid address format";
        default:
            return "Unrecognized error code";
    }
}
