/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "entropy.h"

#include <string.h>

#include "common.h"
#include "flash.h"
#include "rand.h"

#include "stm32f4xx_ll_utils.h"

extern __IO uint32_t uwTick;

uint8_t HW_ENTROPY_DATA[HW_ENTROPY_LEN];
uint8_t SW_ENTROPY_DATA[SW_ENTROPY_LEN] = {0};
static size_t sw_entropy_index = {0};

void collect_hw_entropy(void) {
  // collect entropy from UUID
  uint32_t w = LL_GetUID_Word0();
  memcpy(HW_ENTROPY_DATA, &w, 4);
  w = LL_GetUID_Word1();
  memcpy(HW_ENTROPY_DATA + 4, &w, 4);
  w = LL_GetUID_Word2();
  memcpy(HW_ENTROPY_DATA + 8, &w, 4);

  // set entropy in the OTP randomness block
  if (secfalse == flash_otp_is_locked(FLASH_OTP_BLOCK_RANDOMNESS)) {
    uint8_t entropy[FLASH_OTP_BLOCK_SIZE];
    random_buffer(entropy, FLASH_OTP_BLOCK_SIZE);
    ensure(flash_otp_write(FLASH_OTP_BLOCK_RANDOMNESS, 0, entropy,
                           FLASH_OTP_BLOCK_SIZE),
           NULL);
    ensure(flash_otp_lock(FLASH_OTP_BLOCK_RANDOMNESS), NULL);
  }
  // collect entropy from OTP randomness block
  ensure(flash_otp_read(FLASH_OTP_BLOCK_RANDOMNESS, 0, HW_ENTROPY_DATA + 12,
                        FLASH_OTP_BLOCK_SIZE),
         NULL);
}

void add_sw_entropy(uint8_t *data, size_t data_length) {
  size_t sw_entropy_index_local = sw_entropy_index % sizeof(SW_ENTROPY_DATA);

  SW_ENTROPY_DATA[sw_entropy_index_local] ^= uwTick & 0xff;
  sw_entropy_index_local =
      (sw_entropy_index_local + 1) % sizeof(SW_ENTROPY_DATA);

  for (size_t i = 0; i < data_length; i++) {
    SW_ENTROPY_DATA[sw_entropy_index_local] ^= data[i];
    sw_entropy_index_local =
        (sw_entropy_index_local + 1) % sizeof(SW_ENTROPY_DATA);
  }

  sw_entropy_index = sw_entropy_index_local;
}
