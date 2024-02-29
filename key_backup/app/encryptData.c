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
 * @file      encryptData.c
 * @brief     encryptData for project
 * @copyright 2023 PUFsecurity
 *
 */


#include "libcore.h"
#define BUF_SIZE 17

void usage(char *argv0)
{
    fprintf(stderr, "Usage: %s [-d] [-i input_file] [-o output_file]\n", argv0);
    fprintf(stderr, "   -d  decode\n\n");
}

int main(int argc, char *argv[])
{
    pufs_status_t ret = PUFS_SUCCESS;
    int opt, len, decode = 0, same_io = 0;
    u8 buf[BUF_SIZE] = {0};

    FILE *fp_r, *fp_w;
    char *read_file = NULL;
    char *write_file = NULL;

    while ((opt = getopt(argc, argv, "di:o:")) != -1) {
        switch (opt) {
            case 'd':
                decode = 1;
                break;
            case 'i':
                read_file = optarg;
                break;
            case 'o':
                write_file = optarg;
                break;
            default:
                usage(argv[0]);
                goto EXIT;
        }
    }

    if ((!read_file) || (!write_file)) {
        usage(argv[0]);
        goto EXIT;
    }

    if (strcmp(read_file, write_file) == 0) {
        same_io = 1;
        fp_r = fp_w = fopen(read_file, "rb+");
        if (fp_r == NULL) {
            APP_ERR("fopen %s fail.\n", read_file);
            goto EXIT;
        }
    }
    else {
        fp_r = fopen(read_file, "r");
        if (fp_r == NULL) {
            APP_ERR("fopen %s fail.\n", read_file);
            goto EXIT;
        }

        fp_w = fopen(write_file, "wb");
        if (fp_w == NULL) {
            APP_ERR("fopen %s fail.\n", write_file);
            fclose(fp_r);
            goto EXIT;
        }
    }

    ret = pufs_start(__func__);
    if (ret != PUFS_SUCCESS)
    {
        APP_ERR("pufs_start fail, ret = %d\n", ret);
        goto EXIT;
    }
    enroll();

    do {
        memset(buf, 0, BUF_SIZE);
        len = fread(buf, 1, BUF_SIZE - 1, fp_r);
        if (len < 1) {
            break;
        }

        if (decode == 0) {
            ret = aes_enc((u8 *)buf, len);
            if (ret == PUFS_ERROR_INVALID) {
                printf("Key is invalid!\n");
                goto RET;
            }
            else if (ret != PUFS_SUCCESS) {
                APP_ERR("aes_enc failed, ret = %d", ret);
                goto RET;
            }
        }
        else {
            ret = aes_dec((u8 *)buf, len);
            if (ret == PUFS_ERROR_INVALID) {
                printf("Key is invalid!\n");
                goto RET;
            }
            else if (ret != PUFS_SUCCESS) {
                APP_ERR("aes_dec failed, ret = %d", ret);
                goto RET;
            }
        }

        if (same_io) {
            fseek(fp_w, ftell(fp_w) - len, SEEK_SET);
        }
        ret = fwrite(buf, 1, len, fp_w);
        if (ret < 1) {
            APP_ERR("fwrite fail. ret = %d\n", ret);
            goto RET;
        }
    }while(len == BUF_SIZE - 1);
    if (decode == 0)
        printf("Encrypt data OK\n");
    else
        printf("Decrypt data OK\n");
    ret = 0;
RET:
    pufs_end(__func__);

    fclose(fp_r);
    if (same_io) goto EXIT;
    fclose(fp_w);
EXIT:
    STATISTICS_SHOW();
    return ret;
}



