/***********************************************************************************
 *
 *  Copyright (c) 2023-2024, PUFsecurity
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *  3. Neither the name of PUFsecurity nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 *  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **************************************************************************************/
/**
 * @file      hmacKey.c
 * @brief     hmacKey for project
 * @copyright 2023 PUFsecurity
 *
 */

#include "libcore.h"
#define BUF_SIZE 64

int main(void)
{
    pufs_status_t ret = PUFS_SUCCESS;
    u8 buf[BUF_SIZE] = {0};

    ret = pufs_start(__func__);
    if (ret != PUFS_SUCCESS)
    {
        APP_ERR("pufs_start fail, ret = %d\n", ret);
        goto EXIT;
    }
    enroll();
    ret = hmac_key(buf, BUF_SIZE);
    pufs_end(__func__);

    if (ret == PUFS_ERROR_INVALID) {
        printf("Key is invalid!\n");
        goto EXIT;
    }
    else if (ret != PUFS_SUCCESS) {
        printf("hmac_key FAIL!\n");
        goto EXIT;
    }
    printf("Key HMAC: ");
    for (uint32_t j = 0; j < 32; j++) {
        printf("%02x", buf[j]);
    }
    printf("\n");

EXIT:
    STATISTICS_SHOW();
    return ret;
}



