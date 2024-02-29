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
 * @file      pufs_rt.h
 * @brief     PUFsecurity PUFrt API interface
 * @copyright 2023 PUFsecurity
 */
#ifndef __PUFS_RT_H__
#define __PUFS_RT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pufs_basic.h"
/*****************************************************************************
 * Macros
 ****************************************************************************/
#define UIDLEN              (32)
/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief OTP lock states
 */
typedef enum {
    RT_LCK_NA,  ///< No-Access
    RT_LCK_RO,  ///< Read-Only
    RT_LCK_RW,  ///< Read-Write
    RT_LCK_IVALID,
} pufs_otp_lock_t;
/**
 * @brief PUFrt slots
 */
typedef enum {
    // PUF slots
    PUFSLOT_0,                      ///< PUF slot 0, 256 bits
    DEFAULT_PUFSLOT = PUFSLOT_0,    ///< Default PUF slot
    PUFSLOT_1,                      ///< PUF slot 1, 256 bits
    PUFSLOT_2,                      ///< PUF slot 2, 256 bits
    PUFSLOT_3,                      ///< PUF slot 3, 256 bits
    // OTP key slots
    OTPKEY_0,                       ///< OTP key slot 0, 256 bits
    OTPKEY_1,                       ///< OTP key slot 1, 256 bits
    OTPKEY_2,                       ///< OTP key slot 2, 256 bits
    OTPKEY_3,                       ///< OTP key slot 3, 256 bits
    OTPKEY_4,                       ///< OTP key slot 4, 256 bits
    OTPKEY_5,                       ///< OTP key slot 5, 256 bits
    OTPKEY_6,                       ///< OTP key slot 6, 256 bits
    OTPKEY_7,                       ///< OTP key slot 7, 256 bits
    OTPKEY_8,                       ///< OTP key slot 8, 256 bits
    OTPKEY_9,                       ///< OTP key slot 9, 256 bits
    OTPKEY_10,                      ///< OTP key slot 10, 256 bits
    OTPKEY_11,                      ///< OTP key slot 11, 256 bits
    OTPKEY_12,                      ///< OTP key slot 12, 256 bits
    OTPKEY_13,                      ///< OTP key slot 13, 256 bits
    OTPKEY_14,                      ///< OTP key slot 14, 256 bits
    OTPKEY_15,                      ///< OTP key slot 15, 256 bits
    OTPKEY_16,                      ///< OTP key slot 16, 256 bits
    OTPKEY_17,                      ///< OTP key slot 17, 256 bits
    OTPKEY_18,                      ///< OTP key slot 18, 256 bits
    OTPKEY_19,                      ///< OTP key slot 19, 256 bits
    OTPKEY_20,                      ///< OTP key slot 20, 256 bits
    OTPKEY_21,                      ///< OTP key slot 21, 256 bits
    OTPKEY_22,                      ///< OTP key slot 22, 256 bits
    OTPKEY_23,                      ///< OTP key slot 23, 256 bits
    OTPKEY_24,                      ///< OTP key slot 24, 256 bits
    OTPKEY_25,                      ///< OTP key slot 25, 256 bits
    OTPKEY_26,                      ///< OTP key slot 26, 256 bits
    OTPKEY_27,                      ///< OTP key slot 27, 256 bits
    OTPKEY_28,                      ///< OTP key slot 28, 256 bits
    OTPKEY_29,                      ///< OTP key slot 29, 256 bits
    OTPKEY_30,                      ///< OTP key slot 30, 256 bits
    OTPKEY_31,                      ///< OTP key slot 31, 256 bits
} pufs_rt_slot_t;
/*****************************************************************************
 * Structures
 ****************************************************************************/
/**
 * @brief PUF UID.
 */
typedef struct {
    uint8_t uid[UIDLEN]; ///< UID container
} pufs_uid_st;
/**
 * @brief OTP addressing type.
 */
typedef uint16_t pufs_otp_addr_t;
/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief Export the unique device identity (256-bit).
 *
 * @param[out] uid   The unique device identity.
 * @param[in]  slot  PUF slot.
 * @return           SUCCESS on success, otherwise an error code.
 *
 * @note In PUFcc, only PUFSLOT_0 is available for read. Other 3 PUF slots are
 *        reserved for internal use in cryptographic engines.
 */
pufs_status_t pufs_get_uid(pufs_uid_st *uid, pufs_rt_slot_t slot);
/**
 * @brief Read 32-bit random blocks from RNG.
 *
 * @param[out] rand     Output random blocks
 * @param[in]  numblks  Number of blocks to be generated, each block 32 bits.
 * @return              SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_rand(uint8_t *rand, uint32_t numblks);
/**
 * @brief Read from OTP with boundary check.
 *
 * @param[out] outbuf  OTP data.
 * @param[in]  len     The length of data in bytes.
 * @param[in]  addr    Sarting address of the read.
 * @return             SUCCESS on success, otherwise an error code.
 *
 * @note \em addr must be aligned to 4 bytes boundary
 */
pufs_status_t pufs_read_otp(uint8_t *outbuf, uint32_t len,
                            pufs_otp_addr_t addr);
/**
 * @brief Write to OTP with boundary check.
 *
 * @param[in] inbuf  The data to be written to OTP.
 * @param[in] len    The length of data in bytes.
 * @param[in] addr   Starting OTP address to be programmed.
 * @return           SUCCESS on success, otherwise an error code.
 *
 * @note \em addr must be aligned to 4 bytes boundary
 */
pufs_status_t pufs_program_otp(const uint8_t *inbuf, uint32_t len,
                               pufs_otp_addr_t addr);
/**
 * @brief Set OTP lock state
 *
 * @param[in] addr  Starting OTP address lock state to be set.
 * @param[in] len   The length of OTP data in bytes.
 * @param[in] lock  The lock state.
 * @return          SUCCESS on success, otherwise an error code.
 *
 * @note \em addr must be aligned to 4 bytes boundary
 */
pufs_status_t pufs_lock_otp(pufs_otp_addr_t addr, uint32_t len,
                            pufs_otp_lock_t lock);
/**
 * @brief Import a cleartext key into OTP with boundary check.
 *
 * @param[in] slot     OTP key slot.
 * @param[in] key      The plaintext key to be imported.
 * @param[in] keybits  Key length in bits. (max key bit length: 2047)
 * @return             SUCCESS on success, otherwise an error code.
 *
 * @note Each OTP key slot is 256-bit. For a key of length \f$b\f$ bits, the
 *       slot number \em n (starting with 0) MUST be a multiple of \f$2^k\f$
 *       where \f$k\f$ is the smallest integer such that \f$b \le 256 \cdot
 *       2^k\f$. For example, a 384-bit key can be programmed in OTPKEY_0,
 *       OTPKEY_2, and so forth.
 */
pufs_status_t pufs_program_key2otp(pufs_rt_slot_t slot, const uint8_t *key,
                                   uint32_t keybits);
/**
 * @brief Zeroize PUF slot
 *
 * @param[in] slot  PUF slot.
 * @return          SUCCESS on success, otherwise an error code.
 */
pufs_status_t pufs_zeroize(pufs_rt_slot_t slot);
/**
 * @brief PUFrt post masking
 *
 * @param[in] maskslots  The bitmap of \ref pufs_rt_slot_t slots to be masked.
 * @return               SUCCESS on success, otherwise an error code.
 *
 * @note \em maskslots is constructed by bit-wise or of \ref MASK_BIT outputs
 *       of the PUF slots/OTP key slots. For example, if PUFSLOT_1 and OTPKEY_2
 *       is designed to be masked, the input is \n
 *        MASK_BIT(PUFSLOT_1) | MASK_BIT(OTPKEY_2)
 */
pufs_status_t pufs_post_mask(uint64_t maskslots);
/**
 * @brief Read version and features register value
 *
 * @param[out] version   Version register value
 * @param[out] features  Features register value
 * @return               SUCCESS.
 */
pufs_status_t pufs_rt_version(uint32_t *version, uint32_t *features);
/**
 * @brief Get OTP rwlck value
 *
 * @param[in] addr  The address of the rwlck.
 * @return          The rwlck bits.
 */
pufs_otp_lock_t pufs_get_otp_rwlck(pufs_otp_addr_t addr);

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_RT_H__*/
