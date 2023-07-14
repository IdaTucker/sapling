/*******************************************************************************
*   (c) 2020 Zondax AG
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

#include "index_sapling.h"


uint16_t length_spend_old_data() {
    return 0;
}

uint16_t length_spenddata() {
    return 0;
};

uint16_t length_outputdata() {
    return 0;
};

uint16_t length_spend_new_data() {
    return 0;
};

uint16_t start_sighashdata() {
    return length_t_in_data() + length_spenddata() + length_outputdata();
};
