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

#if !BITCOIN_ONLY

#include "py/objstr.h"

#include "vendor/trezor-crypto/ecash/schnorr.h"
#include "vendor/trezor-crypto/secp256k1.h"

/// package: trezorcrypto.ecash

/// def sign_schnorr(
///     secret_key: bytes,
///     digest: bytes,
/// ) -> bytes:
///     """
///     Uses secret key to produce the Schnorr signature (XEC variant) of the
///     digest.
///     """
STATIC mp_obj_t mod_trezorcrypto_ecash_sign_schnorr(mp_obj_t secret_key,
                                                    mp_obj_t digest) {
  mp_buffer_info_t sk = {0};
  mp_buffer_info_t dig = {0};
  mp_get_buffer_raise(secret_key, &sk, MP_BUFFER_READ);
  mp_get_buffer_raise(digest, &dig, MP_BUFFER_READ);

  if (sk.len != 32) {
    mp_raise_ValueError("Invalid length of secret key");
  }
  if (dig.len != 32) {
    mp_raise_ValueError("Invalid length of digest");
  }

  vstr_t sig = {0};
  vstr_init_len(&sig, SCHNORR_SIG_LENGTH);

  if (0 != schnorr_sign_digest(&secp256k1, (const uint8_t *)sk.buf,
                               (const uint8_t *)dig.buf, (uint8_t *)sig.buf)) {
    vstr_clear(&sig);
    mp_raise_ValueError("Schnorr signing failed");
  }

  return mp_obj_new_str_from_vstr(&mp_type_bytes, &sig);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_ecash_sign_schnorr_obj,
                                 mod_trezorcrypto_ecash_sign_schnorr);

/// def verify_schnorr(public_key: bytes, signature: bytes, digest: bytes) ->
/// bool:
///     """
///     Uses public key to verify the Schnorr signature (XEC variant) of the
///     digest.
///     Returns True on success.
///     """
STATIC mp_obj_t mod_trezorcrypto_ecash_verify_schnorr(mp_obj_t public_key,
                                                      mp_obj_t signature,
                                                      mp_obj_t digest) {
  mp_buffer_info_t pk = {0}, sig = {0}, dig = {0};
  mp_get_buffer_raise(public_key, &pk, MP_BUFFER_READ);
  mp_get_buffer_raise(signature, &sig, MP_BUFFER_READ);
  mp_get_buffer_raise(digest, &dig, MP_BUFFER_READ);

  if (pk.len != 33 && pk.len != 65) {
    return mp_const_false;
  }
  if (sig.len != SCHNORR_SIG_LENGTH) {
    return mp_const_false;
  }
  if (dig.len != 32) {
    return mp_const_false;
  }

  return mp_obj_new_bool(0 == schnorr_verify_digest(&secp256k1,
                                                    (const uint8_t *)pk.buf,
                                                    (const uint8_t *)dig.buf,
                                                    (const uint8_t *)sig.buf));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(mod_trezorcrypto_ecash_verify_schnorr_obj,
                                 mod_trezorcrypto_ecash_verify_schnorr);

STATIC const mp_rom_map_elem_t mod_trezorcrypto_ecash_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ecash)},
    {MP_ROM_QSTR(MP_QSTR_sign_schnorr),
     MP_ROM_PTR(&mod_trezorcrypto_ecash_sign_schnorr_obj)},
    {MP_ROM_QSTR(MP_QSTR_verify_schnorr),
     MP_ROM_PTR(&mod_trezorcrypto_ecash_verify_schnorr_obj)},
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_ecash_globals,
                            mod_trezorcrypto_ecash_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_ecash_module = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mod_trezorcrypto_ecash_globals,
};

#endif  // !BITCOIN_ONLY
