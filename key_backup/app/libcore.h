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

 #ifndef __GENERATEKEY_H__
#define __GENERATEKEY_H__

#include "common.h"

int generate_salt(pufs_bytes_st *salt);
int generate_key(void);

pufs_status_t pufs_start(const char *func);
pufs_status_t pufs_end(const char *func);
pufs_status_t generate_ecdh_kek(packet_st *packet);
pufs_status_t ecdh_keys(packet_st *packet);
int get_macaddr(char *iface, char *mac_addr);
pufs_status_t client_wrap_packet(packet_st *packet);
pufs_status_t client_require_wrap_packet(packet_st *packet);

pufs_status_t server_wrap_packet(packet_st *packet);

pufs_status_t server_import_wrap(packet_st *packet);
pufs_pal_mutex *mutex;
pufs_status_t server_export_to_file(packet_st *packet);
pufs_status_t server_import_from_file(packet_st *packet);
pufs_status_t client_import_wrap(packet_st *packet);
pufs_status_t aes_enc(u8 *buf, uint32_t buf_size);
pufs_status_t aes_dec(u8 *buf, uint32_t buf_size);
pufs_status_t hmac_key(u8 *buf, uint32_t buf_size);
pufs_status_t clear_key(void);
int enroll(void);

#define PUFS_SUCCESS SUCCESS
#define PUFS_ERROR E_ERROR
#define PUFS_ERROR_INVALID E_ERROR

#define APP_LOG_LEVEL_ERROR		1
#define APP_LOG_LEVEL_WARNING	2
#define APP_LOG_LEVEL_INFO		3
#define APP_LOG_LEVEL_DEBUG		4
#define APP_LOG_LEVEL_DEFAULT		APP_LOG_LEVEL_DEBUG	/* default setting */

#define APP_ERR(fmt, ...)  \
    if (APP_LOG_LEVEL_DEFAULT >= APP_LOG_LEVEL_ERROR) \
        printf("[app_err]%s: "fmt"\n", __func__, ##__VA_ARGS__);
#define APP_WARN(fmt, ...) \
    if (APP_LOG_LEVEL_DEFAULT >= APP_LOG_LEVEL_WARNING)   \
        printf("[app_warn]%s: "fmt"\n", __func__, ##__VA_ARGS__);
#define APP_INFO(fmt, ...) \
    if (APP_LOG_LEVEL_DEFAULT >= APP_LOG_LEVEL_INFO)  \
        printf("[app_info]%s "fmt"\n", __func__, ##__VA_ARGS__);
#define APP_DBG(fmt, ...)  \
    if (APP_LOG_LEVEL_DEFAULT >= APP_LOG_LEVEL_DEBUG) \
        printf("[app_dbg]%s: "fmt"\n", __func__, ##__VA_ARGS__);


#define MAX_PATH_LENGTH 128
#define STATISTICS 0

#if STATISTICS
#define TABLE_MAX 128
typedef struct {
    char function_name[64];
    unsigned int function_count;
} statistics_table_st;

statistics_table_st statistics_table[TABLE_MAX] = {0};

#define STATISTICS_FUNC(func) { \
    int i; \
    for (i = 0; i < TABLE_MAX; i++) { \
        if (statistics_table[i].function_count == 0) { \
            strcpy(statistics_table[i].function_name, func); \
            statistics_table[i].function_count++; \
            break; \
        } \
        else if (strcmp(statistics_table[i].function_name, func) == 0) { \
            statistics_table[i].function_count++; \
            break; \
        } \
        else { \
            continue; \
        } \
    } \
    if (i == TABLE_MAX) { \
        printf("%s(%d) i:[%d] %s ERROR!!\n", __func__, __LINE__, i, func); \
    } \
}

#define STATISTICS_SHOW() { \
    int i; \
    printf("STATISTICS_SHOW:\n"); \
    for (i = 0; i < TABLE_MAX; i++) { \
        if (statistics_table[i].function_count != 0) { \
            printf("%s,\t %d\n", statistics_table[i].function_name, statistics_table[i].function_count); \
        } \
        else { \
            break; \
        } \
    } \
}

#else
#define STATISTICS_FUNC(func)
#define STATISTICS_SHOW()
#endif // STATISTICS

#endif /* __GENERATEKEY_H__ */

