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

#include "constants.h"
#include "coin.h"
#include "zxformat.h"
#include "zxmacros.h"
#include "base58.h"
#include "rslib.h"
#include "bech32.h"
#include "sighash.h"
#include "txid.h"
#include "index_sapling.h"
#include "index_NU5.h"
#include "parser_impl.h"
#include "parser_common.h"
#include "common/app_main.h"
#include "lcx_ripemd160.h"

#include "cx.h"

