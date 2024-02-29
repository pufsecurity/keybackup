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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef __PUFS_PUFCC
#include "pufs_crypto.h"
#endif /* __PUFS_PUFCC */

#include "pufs_pkc.h"
#include "pufs_kdf.h"
#include "pufs_rt.h"
#include "pufs_sp38a.h"

#include "pufs_ka.h"
#include "pufs_hmac.h"

#include "libcore.h"
#include "common_extra.h"

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT "44333"
#define EC_POINT_MAXLEN 72
#define RECV_BUF_MAX 2048
#define SEND_BUF_MAX 2048
#define MAC_ADDR_LEN 18
#define MUTEX 0
#define PASSWD_MAX 128
#define KEY_FILE_PATH_MAX 128

//pufs_pal_mutex *mutex;
int mutex_lock;


#define PUFS_TUPLE_BYTES_ARRAY_TO_POINT(array, point) {\
    (point)->out1 = (array).out1;    \
    (point)->out2 = (array).out2;    \
    (point)->len = (array).len;      \
}

//#define _ATT_ __attribute__((__packed__))
#define _ATT_

typedef enum {
    CLIENT,
    SERVER,
} packet_type_t;

typedef enum {
    INIT = 1,
    CONNECTED,
    ECDH_SHARED,
    SERVER_HANDLER,
    CLIENT_HANDLER,
    FINISH,
    ERROR,
} server_state_t;

typedef enum {
    CONNECT_REQ = 1,
    ECDH_EXCHANGE,
    BACKUP_KEY,
    RESTORE_KEY,
    FINAL_RESULT
} server_event_t;

typedef enum {
    SERVER_SUCCESS = 0,
    SERVER_ERROR = 1
} server_resp_t;

typedef enum {
    ECDH_EPHEMERAL_KEY = 1,
    ECDH_STATIC_KEY,
    WRAPPED_KEY,
    HMAC_KEY
} key_type_t;

// ECDH_EXCHANGE packet
typedef struct _ATT_ {
    uint8_t key_number;
} key_num_st;

typedef struct _ATT_ {
	key_type_t key_type;   /* ECDH ephemeral, ECDH static, AES KWP export */
	uint8_t key_len;
} key_st;

// BACKUP_KEY packet
typedef struct _ATT_ {
    uint8_t key_number;
} wrap_key_num_st;

// FINAL_RESULT packet
typedef struct _ATT_ {
    server_event_t event;
    char packet_name[16];
    server_resp_t result;
} result_packet_st;

typedef struct _ATT_ {
    union {
        u8 out1[EC_POINT_MAXLEN];          ///< output array
        u8 x_out[EC_POINT_MAXLEN];         ///< output array for x in public key
        u8 r_out[EC_POINT_MAXLEN];         ///< output array for r in signautre
        const u8 in1[EC_POINT_MAXLEN];     ///< input array
        const u8 x_in[EC_POINT_MAXLEN];    ///< input array for x in public key
        const u8 r_in[EC_POINT_MAXLEN];    ///< input array for r in signautre
    };
    union {
        u8 out2[EC_POINT_MAXLEN];          ///< output array
        u8 y_out[EC_POINT_MAXLEN];         ///< output array for y in public key
        u8 s_out[EC_POINT_MAXLEN];         ///< output array for s in signautre
        const u8 in2[EC_POINT_MAXLEN];     ///< input array
        const u8 y_in[EC_POINT_MAXLEN];    ///< input array for y in public key
        const u8 s_in[EC_POINT_MAXLEN];    ///< input array for s in signautre
    };
    size_t len;                ///< length of the array
} pufs_tuple_bytes_array_st;

typedef struct _ATT_ {
    char packet_name[16];
    uint8_t cipher[128];
    size_t cipher_size;
    uint8_t export_key[128];
    size_t export_key_size;
    uint8_t hmac_key[128];
    size_t hmac_key_size;
    uint8_t macaddr[32];
} wrap_key_st;

typedef struct _ATT_ {
    server_event_t event;
    char packet_name[16];
    uint8_t key_num;
    key_st ecdh_key_ephemeral;
    key_st ecdh_key_static;
    pufs_tuple_bytes_array_st puk_ephemeral;
    pufs_tuple_bytes_array_st puk_static;
} ecdh_packet_st;


typedef struct _ATT_ {
    server_event_t event;
    wrap_key_st wrap_key;
} wrap_packet_st;

typedef void (*CALLBACK)(void *);
typedef struct _ATT_ {
    server_event_t event;
    server_state_t state;
    CALLBACK cb;
} handler_st;


typedef enum {
    BACKUP = 1,
    RESTORE,
} cmd_t;


typedef struct _ATT_ {
    char recv_buf[RECV_BUF_MAX];
    char send_buf[SEND_BUF_MAX];
    int send_buf_size;
    int recv_buf_size;
    pufs_tuple_bytes_st puk_client_e;
    pufs_tuple_bytes_st puk_client_s;
    pufs_tuple_bytes_st puk_server_e;
    pufs_tuple_bytes_st puk_server_s;
    ecdh_packet_st *send_ecdh_packet;
    ecdh_packet_st *recv_ecdh_packet;
    SSL *ssl;
    packet_type_t type;
    char passwd[PASSWD_MAX];
    char key_file_path[KEY_FILE_PATH_MAX];
    cmd_t cmd;
    char macaddress[32];
} packet_st;

#define CLIENT_EPHEMERAL_PRIVATE_SLOT PRK_0  // CLIENT_EPHEMERAL_PRIVATE_SLOT
#define CLIENT_STATIC_PRIVATE_SLOT PRK_1     // CLIENT_STATIC_PRIVATE_SLOT
#define CLIENT_KEK_SLOT SK256_1              // Client kek slot
#define CLIENT_KEY_SLOT SK256_3              // Client key slot
#define CLIENT_PUFSLOT_UID PUFSLOT_0         // Client UID
#define CLIENT_PUFSLOT_ECDH PUFSLOT_1        // Client generate EDCH static private key
#define CLIENT_PUFSLOT_AESKEY PUFSLOT_2      // Client generate AES key

#define SERVER_EPHEMERAL_PRIVATE_SLOT PRK_2  // SERVER_EPHEMERAL_PRIVATE_SLOT
#define SERVER_STATIC_PRIVATE_SLOT PRK_1     // SERVER_STATIC_PRIVATE_SLOT
#define SERVER_WRAP_KEK_SLOT SK256_0         // SERVER wrap key slot for restore
#define SERVER_KEK_SLOT SK256_1              // SERVER kek slot
#define SERVER_KEY_SLOT SK256_2              // SERVER key slot
#define SERVER_PUFSLOT_ECDH PUFSLOT_1        // SERVER generate EDCH static private key
#define SERVER_PUFSLOT_EXPORT PUFSLOT_3      // SERVER export wrap key to file

#endif /* __COMMON_H__ */
