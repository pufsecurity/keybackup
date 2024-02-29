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
 * @file      libcore.c
 * @brief     libcore for project
 * @copyright 2023 PUFsecurity
 *
 */

#include "libcore.h"

pufs_status_t client_import_wrap(packet_st *packet)
{
    pufs_status_t check = PUFS_SUCCESS;
    int ret;
    wrap_packet_st *wrap_packet = (wrap_packet_st *)(packet->recv_buf);
    uint8_t *out = wrap_packet->wrap_key.export_key;
    uint32_t keybits = 256;
    uint32_t kekbits = 256;
    uint32_t kwptype = AES_KW;
    pufs_dgst_st md;
    pufs_bytes_st *key_hmac = PUFS_BYTES_ALLOC(64);

    STATISTICS_FUNC("pufs_import_wrapped_key");
    check = pufs_import_wrapped_key(
            SSKEY, CLIENT_KEY_SLOT, out,
            keybits, CLIENT_KEK_SLOT, kekbits,
            kwptype, NULL);

    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_import_wrapped_key_to_ka fail. check = %d \n", check);
        goto RET;
    }

    STATISTICS_FUNC("pufs_hmac");
    check = pufs_hmac(&md, NULL, 0, PUFSE_SHA_256, SSKEY, CLIENT_KEY_SLOT, 256);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_hmac fail, check = %d", check);
        goto RET;
    }
    memcpy(key_hmac->out, md.dgst, md.dlen);
    key_hmac->len = md.dlen;

    ret = memcmp(wrap_packet->wrap_key.hmac_key, key_hmac->out, 32);
    if (ret == 0) {
        printf("Restore OK\n");
    }
    else {
        printf("Restore Fail!\n");
        check = PUFS_ERROR;
    }
RET:

    return check;
}


pufs_status_t server_import_wrap(packet_st *packet)
{
    pufs_status_t check = PUFS_SUCCESS;
    int ret;
    wrap_packet_st *wrap_packet = (wrap_packet_st *)(packet->recv_buf);
    uint8_t *out = wrap_packet->wrap_key.export_key;
    uint32_t keybits = 256;
    uint32_t kekbits = 256;
    uint32_t kwptype = AES_KW;
    pufs_dgst_st md;
    pufs_bytes_st *key_hmac = PUFS_BYTES_ALLOC(64);

    STATISTICS_FUNC("pufs_import_wrapped_key");

    check = pufs_import_wrapped_key(
            SSKEY, SERVER_KEY_SLOT, out,
            keybits, SERVER_KEK_SLOT, kekbits,
            kwptype, NULL);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_import_wrapped_key_to_ka fail. check = %d \n", check);
        goto RET;
    }

    STATISTICS_FUNC("pufs_hmac");
    check = pufs_hmac(&md, NULL, 0, PUFSE_SHA_256, SSKEY, SERVER_KEY_SLOT, 256);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_hmac fail, check = %d", check);
        goto RET;
    }
    memcpy(key_hmac->out, md.dgst, md.dlen);
    key_hmac->len = md.dlen;
    ret = memcmp(wrap_packet->wrap_key.hmac_key, key_hmac->out, 32);
    if (ret == 0) {
        //APP_DBG("(%d) key match", __LINE__);
    }
    else {
        APP_ERR("(%d) key NO match!!!", __LINE__);
        check = PUFS_ERROR;
        goto RET;
    }
RET:
    return check;
}


pufs_status_t client_require_wrap_packet(packet_st *packet)
{
    pufs_status_t check = PUFS_SUCCESS;
    wrap_packet_st *wrap_packet = (wrap_packet_st *)(packet->send_buf);
    memset(wrap_packet, 0, SEND_BUF_MAX);
    wrap_key_st *wrap_key = &(wrap_packet->wrap_key);
    pufs_dgst_st md;

    packet->send_buf_size = sizeof(wrap_packet_st);
    sprintf(wrap_key->packet_name, "RESTORE_CLIENT");
    sprintf((char*)wrap_key->macaddr, "%s", packet->macaddress);
    wrap_key->export_key_size = 40;
    wrap_key->hmac_key_size = 32;
    wrap_key->cipher_size = 32;

    STATISTICS_FUNC("pufs_hmac");
    check = pufs_hmac(&md, NULL, 0, PUFSE_SHA_256, SWKEY, packet->passwd, 256);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_hmac cipher_hmac fail, ret = %d", check);
        goto RET;
    }
    memcpy(wrap_packet->wrap_key.cipher, md.dgst, 32);
    wrap_packet->event = RESTORE_KEY;
RET:

    return check;
}

pufs_status_t client_wrap_packet(packet_st *packet)
{
    pufs_status_t check = PUFS_SUCCESS;
    wrap_packet_st *wrap_packet = (wrap_packet_st *)(packet->send_buf);
    memset(wrap_packet, 0, SEND_BUF_MAX);
    wrap_key_st *wrap_key = &(wrap_packet->wrap_key);
    uint8_t *out = wrap_packet->wrap_key.export_key;
    uint32_t keybits = 256;
    uint32_t kekbits = 256;
    uint32_t kwptype = AES_KW;
    pufs_dgst_st cipher_hmac;

    packet->send_buf_size = sizeof(wrap_packet_st);
    sprintf(wrap_key->packet_name, "WRAP_CLIENT");

    wrap_key->export_key_size = 40;
    wrap_key->hmac_key_size = 32;
    wrap_key->cipher_size = 32;

    pufs_dgst_st key_hmac;
    check = generate_key();
    if (check != PUFS_SUCCESS) {
        APP_ERR("generate_key fail\n");
        goto EXIT;
    }

    STATISTICS_FUNC("pufs_hmac");
    check = pufs_hmac(&cipher_hmac, NULL, 0, PUFSE_SHA_256, SWKEY, packet->passwd, 256);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_hmac cipher_hmac fail, ret = %d", check);
        goto RET;
    }
    memcpy(wrap_packet->wrap_key.cipher, cipher_hmac.dgst, 32);
    wrap_packet->event = BACKUP_KEY;

    STATISTICS_FUNC("pufs_export_wrapped_key");
    check = pufs_export_wrapped_key(
            SSKEY, CLIENT_KEY_SLOT, out,
            keybits, CLIENT_KEK_SLOT, kekbits,
            kwptype, NULL);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_export_wrapped_key_from_ka fail. check = %d \n", check);
        goto RET;
    }
    STATISTICS_FUNC("pufs_hmac");
    check = pufs_hmac(&key_hmac, NULL, 0, PUFSE_SHA_256, SSKEY, CLIENT_KEY_SLOT, 256);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_hmac fail, ret = %d", check);
        goto RET;
    }
    memcpy(wrap_packet->wrap_key.hmac_key, key_hmac.dgst, 32);
    wrap_packet->wrap_key.hmac_key_size = key_hmac.dlen;
RET:
EXIT:
    return check;
}

pufs_status_t server_wrap_packet(packet_st *packet)
{
    pufs_status_t check = PUFS_SUCCESS;
    wrap_packet_st *wrap_packet = (wrap_packet_st *)(packet->send_buf);
    wrap_key_st *wrap_key = &(wrap_packet->wrap_key);
    uint8_t *out = wrap_packet->wrap_key.export_key;
    uint32_t keybits = 256;
    uint32_t kekbits = 256;
    uint32_t kwptype = AES_KW;

    packet->send_buf_size = sizeof(wrap_packet_st);
    sprintf(wrap_key->packet_name, "WRAP_SERVER");

    wrap_key->export_key_size = 40;
    wrap_key->hmac_key_size = 32;
    wrap_key->cipher_size = 32;

    wrap_packet->event = RESTORE_KEY;

    STATISTICS_FUNC("pufs_export_wrapped_key");
    check = pufs_export_wrapped_key(
            SSKEY, SERVER_KEY_SLOT, out,
            keybits, SERVER_KEK_SLOT, kekbits,
            kwptype, NULL);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_export_wrapped_key_from_ka fail. check = %d \n", check);
        goto RET;
    }

RET:
    return check;

}

static int save_to_file(packet_st *packet)
{
    FILE *fp;
    int len, i, ret = 0;
    char filename[256] = {0};
    wrap_packet_st *wrap_packet = (wrap_packet_st *)(packet->recv_buf);
    wrap_key_st *wrap_key = &(wrap_packet->wrap_key);
    strcat(filename, packet->macaddress);
    strncat(filename, "_", 2);
    len = strlen(filename);
    for (i = 0; i < (int)wrap_key->cipher_size; i++) {
        sprintf(&filename[len + i*2], "%02x", wrap_key->cipher[i]);
    }
    len += i * 2;
    sprintf(&filename[len], ".bin");
    APP_DBG("(%d) filename:[%s]\n", __LINE__, filename);
    fp = fopen(filename, "wb");
    if (fp == NULL) {
        APP_ERR("fopen fail. filename:[%s]\n", filename);
        ret = 1;
        goto EXIT;
    }
    ret = fwrite(wrap_key, sizeof(wrap_key_st), 1, fp);
    if (ret < 1) {
        APP_ERR("fwrite fail. ret = %d\n", ret);
        ret = 2;
        goto RETURN;
    }
    ret = 0;
RETURN:
    fclose(fp);
EXIT:
    return ret;
}


static int read_from_file(packet_st *packet)
{
    FILE *fp;
    int len, i, ret = 0;
    char filename[128];
    wrap_packet_st *wrap_packet = (wrap_packet_st *)(packet->recv_buf);
    wrap_key_st *wrap_key = &(wrap_packet->wrap_key);
    strcpy(filename, packet->key_file_path);
    strcat(filename, (char*)wrap_key->macaddr);
    strncat(filename, "_", 2);
    len = strlen(filename);
    for (i = 0; i < (int)wrap_key->cipher_size; i++) {
        sprintf(&filename[len + i*2], "%02x", wrap_key->cipher[i]);
    }
    len += i * 2;
    sprintf(&filename[len], ".bin");
    APP_DBG("(%d) filename:[%s]\n", __LINE__, filename);

    fp = fopen(filename, "r");
    if (fp == NULL) {
        APP_ERR("fopen fail. filename:[%s]\n", filename);
        ret = 1;
        goto EXIT;
    }
    ret = fread(wrap_key, sizeof(wrap_key_st), 1, fp);
    if (ret < 1) {
        APP_ERR("fread fail. ret = %d\n", ret);
        ret = 2;
        goto RETURN;
    }
    ret = 0;

RETURN:
    fclose(fp);
EXIT:
    return ret;
}


pufs_status_t server_export_to_file(packet_st *packet)
{
    pufs_status_t check = PUFS_SUCCESS;
    wrap_packet_st *wrap_packet = (wrap_packet_st *)(packet->recv_buf);
    wrap_key_st *wrap_key = &(wrap_packet->wrap_key);
    uint8_t *out = wrap_key->export_key;
    uint32_t keybits = 256;
    uint32_t kekbits = 256;
    uint32_t kwptype = AES_KW;

    STATISTICS_FUNC("pufs_kdf");
    check = pufs_kdf(SSKEY, SERVER_KEK_SLOT, kekbits,
            PRF_HMAC, PUFSE_SHA_256, false,
            NULL, 0, 1,
            PUFKEY, SERVER_PUFSLOT_EXPORT, 256,
            NULL, 0,  //salt
            NULL, 0); //info
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_kdf_hkdf_exp fail. check = %d \n", check);
        goto RET;
    }

    STATISTICS_FUNC("pufs_export_wrapped_key");
    check = pufs_export_wrapped_key(
            SSKEY, SERVER_KEY_SLOT, out,
            keybits, SERVER_KEK_SLOT, kekbits,
            kwptype, NULL);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_export_wrapped_key_from_ka fail. check = %d \n", check);
        goto RET;
    }
RET:
    check = save_to_file(packet);
    return check;
}



pufs_status_t server_import_from_file(packet_st *packet)
{
    pufs_status_t check = PUFS_SUCCESS;
    wrap_packet_st *wrap_packet = (wrap_packet_st *)(packet->recv_buf);
    wrap_key_st *wrap_key = &(wrap_packet->wrap_key);
    check = read_from_file(packet);
    if (check != 0) {
        APP_ERR("read_from_file fail. check = %d\n", check);
    }

    memcpy(packet->send_buf, packet->recv_buf, sizeof(wrap_packet_st));

    uint8_t *out = wrap_key->export_key;
    uint32_t keybits = 256;
    uint32_t kekbits = 256;
    uint32_t kwptype = AES_KW;

    STATISTICS_FUNC("pufs_kdf");
    check = pufs_kdf(SSKEY, SERVER_WRAP_KEK_SLOT, kekbits,
            PRF_HMAC, PUFSE_SHA_256, false,
            NULL, 0, 1,
            PUFKEY, SERVER_PUFSLOT_EXPORT, 256,
            NULL, 0,  //salt
            NULL, 0); //info
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_kdf_hkdf_exp fail. check = %d \n", check);
        goto RET;
    }

    STATISTICS_FUNC("pufs_import_wrapped_key");
    check = pufs_import_wrapped_key(
            SSKEY, SERVER_KEY_SLOT, out,
            keybits, SERVER_WRAP_KEK_SLOT, kekbits,
            kwptype, NULL);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_import_wrapped_key_to_ka fail. check = %d \n", check);
        goto RET;
    }

RET:
    return check;

}


pufs_status_t ecdh_keys(packet_st *packet)
{
    pufs_status_t check = PUFS_SUCCESS;
    pufs_bytes_st *salt = PUFS_BYTES_ALLOC(64);
    const pufs_bytes_st info = PTEST_TO_BYTES_ST((uint8_t *)"pufsecurity info", 16);
    pufs_ec_point_st puk;

    check = generate_salt(salt);
    if (check != PUFS_SUCCESS)
    {
        APP_ERR("%s(%d) check:[%d] test ERROR!!\n", __func__, __LINE__, check);
        goto EXIT;
    }

    if (packet->type == CLIENT) {
        STATISTICS_FUNC("pufs_ecp_set_curve_byname");
        check = pufs_ecp_set_curve_byname(NISTB163);
        if (check != PUFS_SUCCESS) {
            APP_ERR("pufs_ecp_set_curve_byname failed, check = %d", check);
            goto RET;
        }
        STATISTICS_FUNC("pufs_ecp_gen_eprk");
        check = pufs_ecp_gen_eprk(CLIENT_EPHEMERAL_PRIVATE_SLOT);
        if (check != PUFS_SUCCESS) {
            APP_ERR("pufs_ecp_gen_eprk failed, check = %d", check);
            goto RET;
        }
        STATISTICS_FUNC("pufs_ecp_gen_sprk");

        check = pufs_ecp_gen_sprk(CLIENT_STATIC_PRIVATE_SLOT,
                CLIENT_PUFSLOT_ECDH,
                salt->out, salt->len,
                info.out, info.len,
                HASH_DEFAULT);
        if (check != PUFS_SUCCESS) {
            APP_ERR("pufs_ecp_gen_sprk failed, check = %d", check);
            goto RET;
        }

        STATISTICS_FUNC("pufs_ecp_gen_puk");
        check = pufs_ecp_gen_puk(&puk, PRKEY, CLIENT_EPHEMERAL_PRIVATE_SLOT);
        if (check != PUFS_SUCCESS) {
            APP_ERR("pufs_ecp_gen_puk puk_ephemeral failed, check = %d", check);
            goto RET;
        }
        memcpy(packet->puk_client_e.x_out, puk.x, puk.qlen);
        memcpy(packet->puk_client_e.y_out, puk.y, puk.qlen);
        packet->puk_client_e.len = puk.qlen;

        STATISTICS_FUNC("pufs_ecp_gen_puk");
        check = pufs_ecp_gen_puk(&puk, PRKEY, CLIENT_STATIC_PRIVATE_SLOT);
        if (check != PUFS_SUCCESS) {
            APP_ERR("pufs_ecp_gen_puk puk_static failed, check = %d", check);
            goto RET;
        }
        memcpy(packet->puk_client_s.x_out, puk.x, puk.qlen);
        memcpy(packet->puk_client_s.y_out, puk.y, puk.qlen);
        packet->puk_client_s.len = puk.qlen;
    }
    else if (packet->type == SERVER) {
        STATISTICS_FUNC("pufs_ecp_set_curve_byname");
        check = pufs_ecp_set_curve_byname(NISTB163);
        if (check != PUFS_SUCCESS) {
            APP_ERR("pufs_ecp_set_curve_byname failed, check = %d", check);
            goto RET;
        }
        STATISTICS_FUNC("pufs_ecp_gen_eprk");
        check = pufs_ecp_gen_eprk(SERVER_EPHEMERAL_PRIVATE_SLOT);
        if (check != PUFS_SUCCESS) {
            APP_ERR("pufs_ecp_gen_eprk failed, check = %d", check);
            goto RET;
        }
        STATISTICS_FUNC("pufs_ecp_gen_sprk");
        check = pufs_ecp_gen_sprk(SERVER_STATIC_PRIVATE_SLOT,
                SERVER_PUFSLOT_ECDH,
                salt->out, salt->len,
                info.out, info.len,
                HASH_DEFAULT);
        if (check != PUFS_SUCCESS) {
            APP_ERR("pufs_ecp_gen_sprk failed, check = %d", check);
            goto RET;
        }
        STATISTICS_FUNC("pufs_ecp_gen_puk");
        check = pufs_ecp_gen_puk(&puk, PRKEY, SERVER_EPHEMERAL_PRIVATE_SLOT);
        if (check != PUFS_SUCCESS) {
            APP_ERR("pufs_ecp_gen_puk puk_ephemeral failed, check = %d", check);
            goto RET;
        }
        memcpy(packet->puk_server_e.x_out, puk.x, puk.qlen);
        memcpy(packet->puk_server_e.y_out, puk.y, puk.qlen);
        packet->puk_server_e.len = puk.qlen;

        STATISTICS_FUNC("pufs_ecp_gen_puk");
        check = pufs_ecp_gen_puk(&puk, PRKEY, SERVER_STATIC_PRIVATE_SLOT);
        if (check != PUFS_SUCCESS) {
            APP_ERR("pufs_ecp_gen_puk puk_static failed, check = %d", check);
            goto RET;
        }
        memcpy(packet->puk_server_s.x_out, puk.x, puk.qlen);
        memcpy(packet->puk_server_s.y_out, puk.y, puk.qlen);
        packet->puk_server_s.len = puk.qlen;
    }
    else {
        APP_ERR("unknow type\n");
    }

RET:
EXIT:
    return check;
}


pufs_status_t generate_ecdh_kek(packet_st *packet)
{
    pufs_status_t check = PUFS_SUCCESS;
    pufs_dgst_st key_hmac;
    pufs_ec_point_st puk_e, puk_s;
    memset(&puk_e, 0, sizeof(pufs_ec_point_st));
    memset(&puk_s, 0, sizeof(pufs_ec_point_st));

    pufs_key_st *prk_ephemeral;
    pufs_key_st *prk_ephemeral_client = CREATE_PUFS_KEY_ST(PRKEY, CLIENT_EPHEMERAL_PRIVATE_SLOT, 163);
    pufs_key_st *prk_ephemeral_server = CREATE_PUFS_KEY_ST(PRKEY, SERVER_EPHEMERAL_PRIVATE_SLOT, 163);

    pufs_key_st *prk_static;
    pufs_key_st *prk_static_client = CREATE_PUFS_KEY_ST(PRKEY, CLIENT_STATIC_PRIVATE_SLOT, 163);
    pufs_key_st *prk_static_server = CREATE_PUFS_KEY_ST(PRKEY, SERVER_STATIC_PRIVATE_SLOT, 163);

    pufs_key_st *kek_slot;
    pufs_key_st *kek_slot_client = CREATE_PUFS_KEY_ST(SSKEY, CLIENT_KEK_SLOT, 256);
    pufs_key_st *kek_slot_server = CREATE_PUFS_KEY_ST(SSKEY, SERVER_KEK_SLOT, 256);

    if (packet->type == CLIENT) {
        prk_ephemeral = prk_ephemeral_client;
        prk_static = prk_static_client;
        kek_slot = kek_slot_client;
        memcpy(puk_e.x, packet->puk_server_e.x_out,  packet->puk_server_e.len);
        memcpy(puk_e.y, packet->puk_server_e.y_out,  packet->puk_server_e.len);
        puk_e.qlen = packet->puk_server_e.len;
        memcpy(puk_s.x, packet->puk_server_s.x_out,  packet->puk_server_s.len);
        memcpy(puk_s.y, packet->puk_server_s.y_out,  packet->puk_server_s.len);
        puk_s.qlen = packet->puk_server_s.len;
    }
    else if (packet->type == SERVER) {
        prk_ephemeral = prk_ephemeral_server;
        prk_static = prk_static_server;
        kek_slot = kek_slot_server;
        memcpy(puk_e.x, packet->puk_client_e.x_out,  packet->puk_client_e.len);
        memcpy(puk_e.y, packet->puk_client_e.y_out,  packet->puk_client_e.len);
        puk_e.qlen = packet->puk_client_e.len;
        memcpy(puk_s.x, packet->puk_client_s.x_out,  packet->puk_client_s.len);
        memcpy(puk_s.y, packet->puk_client_s.y_out,  packet->puk_client_s.len);
        puk_s.qlen = packet->puk_client_s.len;
    }
    else {
        APP_ERR("(%d) Unknown packet type:[%d]\n", __LINE__, packet->type);
        check = PUFS_ERROR;
        goto EXIT;
    }

    STATISTICS_FUNC("pufs_ecp_set_curve_byname");
    check = pufs_ecp_set_curve_byname(NISTB163);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_ecp_set_curve_byname failed, check = %d", check);
        goto RET;
    }
    STATISTICS_FUNC("pufs_ecp_ecccdh_2e2s");
    check = pufs_ecp_ecccdh_2e2s(puk_e, puk_s, prk_ephemeral->keyslot, prk_ephemeral->key_storage, prk_static->keyslot, NULL);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_ecp_ecccdh_2e2s failed, check = %d", check);
        goto RET;
    }

    STATISTICS_FUNC("pufs_kdf");
    check = pufs_kdf(SSKEY, kek_slot->keyslot, 256,
            PRF_HMAC, PUFSE_SHA_256, false,
            NULL, 0, 1,
            SHARESEC, SHARESEC_0, 0,
            NULL, 0,  //salt
            NULL, 0); //info
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_kdf_hkdf fail. check = %d", check);
        goto RET;
    }

    STATISTICS_FUNC("pufs_hmac");
    check = pufs_hmac(&key_hmac, NULL, 0, PUFSE_SHA_256, SSKEY, kek_slot->keyslot, 256);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_hmac kek failed, ret = %d", check);
        goto RET;
    }

RET:
EXIT:
    return check;
}



pufs_status_t pufs_start(const char *func __attribute__((unused)))
{
#if MUTEX
    int mutex_lock;

    STATISTICS_FUNC("pufs_pal_mutex_create");
    mutex = pufs_pal_mutex_create();
    if (mutex == NULL) {
        APP_ERR("%s", "Create mutex failed");
        return -1;
    }

    STATISTICS_FUNC("pufs_pal_mutex_trylock");
    mutex_lock = pufs_pal_mutex_trylock(mutex);
    if (mutex_lock) {
        PUFS_INFO("Some instance might be already running, ret = %d", mutex_lock);
        return -1;
    } else {
        PUFS_INFO("Acquired Lock ret = %d", mutex_lock);
    }
#endif
    pufs_status_t ret = PUFS_SUCCESS;
    // First, init neccesary module
    STATISTICS_FUNC("pufs_cmd_iface_init");
    ret = pufs_cmd_iface_init();
    if (ret != PUFS_SUCCESS) {
        APP_ERR("pufs_cmd_iface_init failed, ret = %d", ret);
    }

    return ret;
}

pufs_status_t pufs_end(const char *func __attribute__((unused)))
{
    pufs_status_t ret = PUFS_SUCCESS;
    // Last, release the modules

    STATISTICS_FUNC("pufs_cmd_iface_deinit");
    ret = pufs_cmd_iface_deinit();
    if (ret != PUFS_SUCCESS) {
        APP_ERR("pufs_cmd_iface_deinit failed, ret = %d", ret);
    }
#if MUTEX
    STATISTICS_FUNC("pufs_pal_mutex_unlock");
    pufs_pal_mutex_unlock(mutex);
    STATISTICS_FUNC("pufs_pal_mutex_destroy");
    pufs_pal_mutex_destroy(mutex);
#endif
    return ret;
}

int get_net_interface(char *interfaceNames)
{
    FILE *file;
    file = popen("ls /sys/class/net", "r");
    if (file == NULL) {
        APP_ERR("The path error:  /sys/class/net\n");
        return 1;
    }
    while (fgets(interfaceNames, MAX_PATH_LENGTH, file) != NULL) {
        interfaceNames[strcspn(interfaceNames, "\n")] = '\0';
        if ((strncmp(interfaceNames, "docker", 6) == 0) ||
            (strncmp(interfaceNames, "br-", 3) == 0) ||
            (strncmp(interfaceNames, "lo", 2) == 0) ||
            (strncmp(interfaceNames, "sit", 3) == 0)) {
            continue;
        }
        else {
            break;
        }
    }
    return 0;
}


int get_macaddr(char *iface, char *mac_addr)
{
    int ret = 0;
    FILE *fp;
    char path[MAX_PATH_LENGTH * 2];
    char *p;

    sprintf(path, "/sys/class/net/%s/address", iface);
    fp = fopen(path, "r");
    if (fp == NULL) {
        perror("fopen");
        APP_ERR("Open file %s failed\n", path);
        ret = 1;
    }
    else {
        p = fgets(mac_addr, MAC_ADDR_LEN, fp);
        fclose(fp);
        if (p == NULL) {
        	APP_ERR("fgets mac address failed\n");
        	ret = 1;
        }
    }

    return ret;
}

static pufs_status_t pufs_gen_aes_key(pufs_bytes_st *salt)
{
    pufs_status_t check = PUFS_SUCCESS;

    salt->len = 64;	// Max salt length is 64
    STATISTICS_FUNC("pufs_kdf");
    check = pufs_kdf(SSKEY, CLIENT_KEY_SLOT, 256,
            PRF_HMAC, PUFSE_SHA_256, false,
            NULL, 0, 1,
            PUFKEY, CLIENT_PUFSLOT_AESKEY, 256,
            NULL, 0,  //salt
            NULL, 0); //info
    if (check != PUFS_SUCCESS) APP_ERR("pufs_kdf_hkdf fail, ret = %d", check);

    return check;
}

int generate_salt(pufs_bytes_st *salt)
{
    pufs_status_t check = PUFS_SUCCESS;
    uint32_t mac_length;
    pufs_uid_st uid;
    char interfaceNames[MAX_PATH_LENGTH];

    // get UID from PUFS
    if (get_net_interface(interfaceNames) != 0) {
        check = 1;
        goto RET;
    }
    get_macaddr(interfaceNames, (char *)(salt->out));
    mac_length = strlen((char *)(salt->out));
    salt->out = salt->out + mac_length;
    salt->len = salt->len - mac_length;

    STATISTICS_FUNC("pufs_get_uid");
    check = pufs_get_uid(&uid, CLIENT_PUFSLOT_UID);
    if (check != PUFS_SUCCESS) {
        APP_ERR("pufs_get_uid, check = %d", check);
        goto RET;
    }
    memcpy(salt->out, uid.uid, UIDLEN);
    salt->out = salt->out - mac_length;
    salt->len = salt->len + mac_length;
RET:
    return check;

}


int enroll(void)
{
    int ret = 0;
    /*
    char *enroll_lock_file = "/run/enroll.lock";
    char cmd[128];
    if (access(enroll_lock_file, F_OK) == 0) {
        //APP_DBG("Enrolled. %s exist!!\n", enroll_lock_file);
    }
    else {
        STATISTICS_FUNC("rt_write_enroll");
        rt_write_enroll();
        sprintf(cmd, "touch %s", enroll_lock_file);
        ret = system(cmd);
    }
    */
    return ret;
}

int generate_key(void)
{
    pufs_status_t check = PUFS_SUCCESS;
    pufs_bytes_st *salt = PUFS_BYTES_ALLOC(128);

    check = generate_salt(salt);
    if (check != PUFS_SUCCESS)
    {
        APP_ERR("generate_salt fail, check = %d\n", check);
        goto RET;
    }

    check = pufs_gen_aes_key(salt);
    if (check != PUFS_SUCCESS)
    {
        APP_ERR("pufs_gen_aes_key fail, check = %d\n", check);
        goto RET;
    }

RET:
    return check;
}


pufs_status_t aes_enc(u8 *buf, uint32_t buf_size)
{
    pufs_status_t check = PUFS_SUCCESS;
    pufs_bytes_st *out_ct = CREATE_PUFS_BYTES_OUT(buf, buf_size);
    pufs_bytes_st *iv = PUFS_BYTES_ALLOC(64);
    pufs_dgst_st md;

    STATISTICS_FUNC("pufs_hmac");
    check = pufs_hmac(&md, NULL, 0, PUFSE_SHA_256, SSKEY, CLIENT_KEY_SLOT, 256);
    if (check != PUFS_SUCCESS)
    {
        goto RET;
    }
    memcpy(iv->out, md.dgst, md.dlen);
    iv->len = md.dlen;
    STATISTICS_FUNC("pufs_enc_ofb");
    check = pufs_enc_ofb(out_ct->out, (uint32_t *)&(out_ct->len),
        buf, buf_size,
        AES,
        SSKEY, CLIENT_KEY_SLOT, 256,
        iv->out);
RET:

    return check;
}


pufs_status_t aes_dec(u8 *buf, uint32_t buf_size)
{
    pufs_status_t check = PUFS_SUCCESS;
    pufs_bytes_st *out_pt = CREATE_PUFS_BYTES_OUT(buf, buf_size);
    pufs_bytes_st *iv = PUFS_BYTES_ALLOC(64);
    pufs_dgst_st md;

    STATISTICS_FUNC("pufs_hmac");
    check = pufs_hmac(&md, NULL, 0, PUFSE_SHA_256, SSKEY, CLIENT_KEY_SLOT, 256);
    if (check != PUFS_SUCCESS)
    {
        APP_ERR("pufs_hmac fail, check = %d\n", check);
        goto RET;
    }
    memcpy(iv->out, md.dgst, md.dlen);
    iv->len = md.dlen;

    STATISTICS_FUNC("pufs_dec_ofb");
    check = pufs_dec_ofb(out_pt->out, (uint32_t *)&(out_pt->len),
        buf, buf_size,
        AES,
        SSKEY, CLIENT_KEY_SLOT, 256,
        iv->out);

RET:
    return check;
}

pufs_status_t hmac_key(u8 *buf, uint32_t buf_size)
{
    pufs_status_t check = PUFS_SUCCESS;
    pufs_dgst_st key_hmac;

    STATISTICS_FUNC("pufs_hmac");
    check = pufs_hmac(&key_hmac, NULL, 0, PUFSE_SHA_256, SSKEY, CLIENT_KEY_SLOT, 256);
    memcpy(buf, key_hmac.dgst, buf_size);
    return check;
}

pufs_status_t clear_key(void)
{
    pufs_status_t check = PUFS_SUCCESS;
    check = pufs_start(__func__);
    if (check != PUFS_SUCCESS)
    {
        APP_ERR("pufs_start fail, check = %d\n", check);
        goto EXIT;
    }
    STATISTICS_FUNC("pufs_clear_key");
    check = pufs_clear_key(SSKEY, CLIENT_KEY_SLOT, 256);
    pufs_end(__func__);

EXIT:
    return check;

}


