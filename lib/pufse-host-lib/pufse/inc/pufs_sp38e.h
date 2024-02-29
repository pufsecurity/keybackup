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
 * @file      pufs_sp38e.h
 * @brief     PUFsecurity sp38e API interface
 * @copyright 2023 PUFsecurity
 */

#ifndef __PUFS_SP38E_H__
#define __PUFS_SP38E_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pufs_basic.h"
#include "pufs_ka.h"
/*****************************************************************************
 * Type definitions
 ****************************************************************************/
typedef struct pufs_sp38e_context pufs_sp38e_ctx;
/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief Obtain a pointer to SP38E internal context
 *
 * @return A pointer to SP38E internal context, or NULL if error
 */
pufs_sp38e_ctx *pufs_sp38e_ctx_new(void);
/**
 * @brief Free a pointer to SP38E internal context
 *
 * @param[in] sp38e_ctx  A pointer to SP38E context.
 */
void pufs_sp38e_ctx_free(pufs_sp38e_ctx *sp38e_ctx);
/**
 * @brief Initialize XTS encryptor
 *
 * @param[in] sp38e_ctx  SP38E context to be initialized.
 * @param[in] cipher     Block cipher algorithm.
 * @param[in] keytype1   Key1 key type.
 * @param[in] keyaddr1   Key1 key address.
 * @param[in] keybits    Each key length in bits.
 * @param[in] keytype2   Key2 key type.
 * @param[in] keyaddr2   Key2 key address.
 * @param[in] i          Tweak value.
 * @param[in] j          Sequence number of the first input data.
 * @return               SUCCESS on success, otherwise an error code.
 *
 * @note \em keyaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
 *       element, or a memory address according to the \em keytype setting.
 * @warning Set \ref PUFKEY or \ref SHARESEC as \em keytype is not allowed.
 */
#define pufs_enc_xts_init(sp38e_ctx, cipher, keytype1, keyaddr1, keybits, \
                          keytype2, keyaddr2, i, j) \
    _pufs_enc_xts_init(sp38e_ctx, cipher, keytype1, (size_t)keyaddr1, keybits, \
                       keytype2, (size_t)keyaddr2, i, j)
/**
 * @brief XTS encryptor initializer with keyaddr type casting
 *
 * @warning DO NOT call this function directly. Use pufs_enc_xts_init() instead.
 */
pufs_status_t _pufs_enc_xts_init(pufs_sp38e_ctx *sp38e_ctx,
                                 pufs_cipher_t cipher,
                                 pufs_key_type_t keytype1,
                                 size_t keyaddr1,
                                 uint32_t keybits,
                                 pufs_key_type_t keytype2,
                                 size_t keyaddr2,
                                 const uint8_t *i,
                                 uint32_t j);
/**
 * @brief Input data into XTS encryptor
 *
 * @param[in]  sp38e_ctx  SP38E context.
 * @param[out] out        Output data.
 * @param[out] outlen     Output data length in bytes.
 * @param[in]  in         Input data.
 * @param[in]  inlen      Input data length in bytes.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_enc_xts_update(pufs_sp38e_ctx *sp38e_ctx,
                                  uint8_t *out,
                                  uint32_t *outlen,
                                  const uint8_t *in,
                                  uint32_t inlen);
/**
 * @brief Finalize XTS encryptor
 *
 * @param[in]  sp38e_ctx  SP38E context.
 * @param[out] out        Output data.
 * @param[out] outlen     Output data length in bytes.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_enc_xts_final(pufs_sp38e_ctx *sp38e_ctx,
                                 uint8_t *out,
                                 uint32_t *outlen);
/**
 * @brief Encryption using XTS mode.
 *
 * @param[out] out       Output data.
 * @param[out] outlen    Output data length in bytes.
 * @param[in]  in        Input data.
 * @param[in]  inlen     Input data length in bytes.
 * @param[in]  cipher    Block cipher algorithm.
 * @param[in]  keytype1  Key1 key type.
 * @param[in]  keyaddr1  Key1 key address.
 * @param[in]  keybits   Each key length in bits.
 * @param[in]  keytype2  Key2 key type.
 * @param[in]  keyaddr2  Key2 key address.
 * @param[in]  i         Tweak value.
 * @param[in]  j         Sequence number of the first input data.
 * @return               SUCCESS on success, otherwise an error code.
 *
 * @note \em keyaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
 *       element, or a memory address according to the \em keytype setting.
 * @warning Set \ref PUFKEY or \ref SHARESEC as \em keytype is not allowed.
 */
#define pufs_enc_xts(out, outlen, in, inlen, cipher, keytype1, keyaddr1, \
                     keybits, keytype2, keyaddr2, i, j) \
    _pufs_enc_xts(out, outlen, in, inlen, cipher, keytype1, (size_t)keyaddr1,\
                  keybits, keytype2, (size_t)keyaddr2, i, j)
/**
 * @brief Encryption using XTS mode with keyaddr type casting.
 *
 * @warning DO NOT call this function directly. Use pufs_enc_xts() instead.
 */
pufs_status_t _pufs_enc_xts(uint8_t *out,
                            uint32_t *outlen,
                            const uint8_t *in,
                            uint32_t inlen,
                            pufs_cipher_t cipher,
                            pufs_key_type_t keytype1,
                            size_t keyaddr1,
                            uint32_t keybits,
                            pufs_key_type_t keytype2,
                            size_t keyaddr2,
                            const uint8_t *i,
                            uint32_t j);
/**
 * @brief Initialize XTS decryptor
 *
 * @param[in] sp38e_ctx  SP38E context to be initialized.
 * @param[in] cipher     Block cipher algorithm.
 * @param[in] keytype1   Key1 key type.
 * @param[in] keyaddr1   Key1 key address.
 * @param[in] keybits    Each key length in bits.
 * @param[in] keytype2   Key2 key type.
 * @param[in] keyaddr2   Key2 key address.
 * @param[in] i          Tweak value.
 * @param[in] j          Sequence number of the first input data.
 * @return               SUCCESS on success, otherwise an error code.
 *
 * @note \em keyaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
 *       element, or a memory address according to the \em keytype setting.
 * @warning Set \ref PUFKEY or \ref SHARESEC as \em keytype is not allowed.
 */
#define pufs_dec_xts_init(sp38e_ctx, cipher, keytype1, keyaddr1, keybits, \
                          keytype2, keyaddr2, i, j) \
    _pufs_dec_xts_init(sp38e_ctx, cipher, keytype1, (size_t)keyaddr1, keybits, \
                       keytype2, (size_t)keyaddr2, i, j)
/**
 * @brief XTS decryptor initializer with keyaddr type casting
 *
 * @warning DO NOT call this function directly. Use pufs_dec_xts_init() instead.
 */
pufs_status_t _pufs_dec_xts_init(pufs_sp38e_ctx *sp38e_ctx,
                                 pufs_cipher_t cipher,
                                 pufs_key_type_t keytype1,
                                 size_t keyaddr1,
                                 uint32_t keybits,
                                 pufs_key_type_t keytype2,
                                 size_t keyaddr2,
                                 const uint8_t *i,
                                 uint32_t j);
/**
 * @brief Input data into XTS decryptor
 *
 * @param[in]  sp38e_ctx  SP38E context.
 * @param[out] out        Output data.
 * @param[out] outlen     Output data length in bytes.
 * @param[in]  in         Input data.
 * @param[in]  inlen      Input data length in bytes.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_dec_xts_update(pufs_sp38e_ctx *sp38e_ctx,
                                  uint8_t *out,
                                  uint32_t *outlen,
                                  const uint8_t *in,
                                  uint32_t inlen);
/**
 * @brief Finalize XTS decryptor
 *
 * @param[in]  sp38e_ctx  SP38E context.
 * @param[out] out        Output data.
 * @param[out] outlen     Output data length in bytes.
 * @return                SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_dec_xts_final(pufs_sp38e_ctx *sp38e_ctx,
                                 uint8_t *out,
                                 uint32_t *outlen);
/**
 * @brief Decryption using XTS mode.
 *
 * @param[out] out       Output data.
 * @param[out] outlen    Output data length in bytes.
 * @param[in]  in        Input data.
 * @param[in]  inlen     Input data length in bytes.
 * @param[in]  cipher    Block cipher algorithm.
 * @param[in]  keytype1  Key1 key type.
 * @param[in]  keyaddr1  Key1 key address.
 * @param[in]  keybits   Each key length in bits.
 * @param[in]  keytype2  Key2 key type.
 * @param[in]  keyaddr2  Key2 key address.
 * @param[in]  iv        Initial vector.
 * @param[in]  csmode    Ciphertext-stealing mode.
 * @return               SUCCESS on success, otherwise an error code.
 *
 * @note \em keyaddr may be a \ref pufs_rt_slot_t element, a \ref pufs_ka_slot_t
 *       element, or a memory address according to the \em keytype setting.
 * @warning Set \ref PUFKEY or \ref SHARESEC as \em keytype is not allowed.
 */
#define pufs_dec_xts(out, outlen, in, inlen, cipher, keytype1, keyaddr1, \
                     keybits, keytype2, keyaddr2, i, j) \
    _pufs_dec_xts(out, outlen, in, inlen, cipher, keytype1, (size_t)keyaddr1,\
                  keybits, keytype2, (size_t)keyaddr2, i, j)
/**
 * @brief Decryption using XTS mode with keyaddr type casting.
 *
 * @warning DO NOT call this function directly. Use pufs_dec_xts() instead.
 */
pufs_status_t _pufs_dec_xts(uint8_t *out,
                            uint32_t *outlen,
                            const uint8_t *in,
                            uint32_t inlen,
                            pufs_cipher_t cipher,
                            pufs_key_type_t keytype1,
                            size_t keyaddr1,
                            uint32_t keybits,
                            pufs_key_type_t keytype2,
                            size_t keyaddr2,
                            const uint8_t *i,
                            uint32_t j);
#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_CMD_SP38E_H__*/
