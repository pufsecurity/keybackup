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
 * @file      test.c
 * @brief     test flow for project
 * @copyright 2023 PUFsecurity
 *
 */


#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pufs_pal.h"
#include "pufs_log.h"
#ifdef __PUFS_PUFCC
#include "pufs_crypto.h"
#endif /* __PUFS_PUFCC */
#include "pufs_pal_mutex.h"
#include "pufs_pal_mutex_plat.h"
#include "pufs_memory_map.h"
#include "pufs_common.h"

int main(void)
{
    pufs_status_t ret;
    pufs_pal_mutex *mutex;
    int mutex_lock;

    mutex = pufs_pal_mutex_create();
    if (mutex == NULL) {
        PUFS_ERR("%s", "Create mutex failed");
        return 0;
    }

    mutex_lock = pufs_pal_mutex_trylock(mutex);
    if (mutex_lock) {
        PUFS_INFO("Some instance might be already running, ret = %d", mutex_lock);
        return 0;
    } else {
        PUFS_INFO("Acquired Lock ret = %d", mutex_lock);
    }

    // First, init neccesary module
    ret = pufs_module_init(PUFIOT_ADDR_START, PUFIOT_MAP_SIZE);
    if (ret != PUFS_SUCCESS) {
        PUFS_ERR("pufs_module_init failed, ret = %d", ret);
    }

    // Second, implement your own logic
    /**
     * Put your implementation code here
     * e.g.1 Invoke provided test functions:
     * pufs_rt_read_puf_test();
     *
     * e.g.2 Directly invoke pufs API functions:
     * uint32_t r1;
     * pufs_rand((uint8_t*)&r1, 1));
     */

    // Last, release the modules
    ret = pufs_exit();
    if (ret != PUFS_SUCCESS) {
        PUFS_ERR("pufs_exit failed, ret = %d", ret);
    }

    pufs_pal_mutex_unlock(mutex);
    pufs_pal_mutex_destroy(mutex);

    return 0;
}
