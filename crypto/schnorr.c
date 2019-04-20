/**
 * Copyright (c) 2021 The Bitcoin ABC developers
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "hmac_drbg.h"
#include "memzero.h"
#include "rfc6979.h"
#include "schnorr.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int jacobi(const bignum256 *_n, const bignum256 *_k) {
  int t = 0;
  int k_is_one;
  uint32_t r;
  bignum256 n, k, temp;

  assert(!bn_is_zero(_k) && bn_is_odd(_k));

  bn_copy(_n, &n);
  bn_copy(_k, &k);

  bn_mod(&n, &k);

  while (!bn_is_zero(&n)) {
    while (bn_is_even(&n)) {
      bn_rshift(&n);
      r = k.val[0] & 0x07;
      t ^= (r == 3 || r == 5);
    }

    bn_cmov(&temp, 0, &n, &n);
    bn_cmov(&n, 0, &k, &k);
    bn_cmov(&k, 0, &temp, &temp);

    t ^= ((n.val[0] & k.val[0] & 3) == 3);

    bn_mod(&n, &k);
  }

  k_is_one = bn_is_one(&k);

  // Cleanup
  memzero(&n, sizeof(n));
  memzero(&k, sizeof(k));
  memzero(&temp, sizeof(temp));

  // Map t: [0] => 1, [1] => -1
  t = -2 * t + 1;

  return k_is_one * t;
}

int is_non_quad_residue(const bignum256 *n, const bignum256 *prime) {
  return jacobi(n, prime) == -1;
}

// Compute sha256(sha256(msg))
void double_sha256(const uint8_t *msg, uint32_t msg_len, uint8_t digest[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX ctx;

  sha256_Init(&ctx);
  sha256_Update(&ctx, msg, msg_len);
  sha256_Final(&ctx, digest);
  sha256_Init(&ctx);
  sha256_Update(&ctx, digest, SHA256_DIGEST_LENGTH);
  sha256_Final(&ctx, digest);
}

void init_rfc6979_schnorr(const uint8_t *priv_key, const uint8_t *hash, rfc6979_state *state) {
  uint8_t hmac_data[SHA256_DIGEST_LENGTH + 16];

  memcpy(hmac_data, hash, 32);
  memcpy(hmac_data + SHA256_DIGEST_LENGTH, "Schnorr+SHA256  ", 16);

  hmac_drbg_init(state, priv_key, 32, hmac_data, SHA256_DIGEST_LENGTH + 16);
}

/*
 * Generate k deterministically.
 * Init the HMAC with additional data specific to Schnorr. This prevents from
 * leaking the private key in the case the same message is signed with both
 * Schnorr and ECDSA.
 */
int generate_k_schnorr(const ecdsa_curve *curve, bignum256 *k, rfc6979_state *state) {
  int i;

  for (i = 0; i < 10000; i++) {
    generate_k_rfc6979(k, state);
    // If k is too big or too small, we don't like it
    if (bn_is_zero(k) || !bn_is_less(k, &curve->order)) {
      continue;
    }

    return 0;
  }

  return 1;
}

// e = H(Rx, pub_key, msg_hash)
static void calc_e(const ecdsa_curve *curve, const bignum256 *Rx,
                   const uint8_t pub_key[33], const uint8_t *msg_hash,
                   bignum256 *e) {
  uint8_t Rxbuf[32];
  SHA256_CTX ctx;
  uint8_t digest[SHA256_DIGEST_LENGTH];

  bn_write_be(Rx, Rxbuf);

  sha256_Init(&ctx);
  sha256_Update(&ctx, Rxbuf, 32);
  sha256_Update(&ctx, pub_key, 33);
  sha256_Update(&ctx, msg_hash, SHA256_DIGEST_LENGTH);
  sha256_Final(&ctx, digest);

  bn_read_be(digest, e);
  bn_fast_mod(e, &curve->order);
  bn_mod(e, &curve->order);
}

int schnorr_sign(const ecdsa_curve *curve, const uint8_t *priv_key,
                 const uint8_t *msg, const uint32_t msg_len,
                 uint8_t *sign) {
  uint8_t digest[SHA256_DIGEST_LENGTH];

  double_sha256(msg, msg_len, digest);

  return schnorr_sign_digest(curve, priv_key, digest, sign);
}

int schnorr_sign_digest(const ecdsa_curve *curve, const uint8_t *priv_key,
                 const uint8_t *digest, uint8_t *sign) {
  uint8_t pub_key[33];
  curve_point R;
  bignum256 private_key_scalar, e, s, k;
  rfc6979_state rng = {0};

  ecdsa_get_public_key33(curve, priv_key, pub_key);

  // Compute k
  init_rfc6979_schnorr(priv_key, digest, &rng);
  if (generate_k_schnorr(curve, &k, &rng) != 0) {
    memzero(&k, sizeof(k));
    return 1;
  }

  // Compute R = k * G
  point_multiply(curve, &k, &curve->G, &R);

  // If R.y is not a quadratic residue, negate the nonce
  bn_normalize(&k);
  bn_cnegate(is_non_quad_residue(&R.y, &curve->prime), &k, &curve->order);
  bn_mod(&k, &curve->order);

  bn_mod(&R.x, &curve->order);
  bn_write_be(&R.x, sign);

  // Compute e = H(Rx, pub_key, msg_hash)
  calc_e(curve, &R.x, pub_key, digest, &e);

  // Compute s = k + e * priv_key
  bn_copy(&e, &s);
  bn_read_be(priv_key, &private_key_scalar);
  bn_multiply(&private_key_scalar, &s, &curve->order);
  memzero(&private_key_scalar, sizeof(private_key_scalar));
  bn_addmod(&s, &k, &curve->order);
  memzero(&k, sizeof(k));
  bn_fast_mod(&s, &curve->order);
  bn_mod(&s, &curve->order);
  bn_write_be(&s, sign + 32);

  if (bn_is_zero(&R.x) || bn_is_zero(&s)) {
    return 2;
  }

  return 0;
}

int schnorr_verify(const ecdsa_curve *curve, const uint8_t *pub_key,
                   const uint8_t *msg, const uint32_t msg_len,
                   const uint8_t *sign) {
  uint8_t digest[SHA256_DIGEST_LENGTH];

  double_sha256(msg, msg_len, digest);

  return schnorr_verify_digest(curve, pub_key, digest, sign);
}

int schnorr_verify_digest(const ecdsa_curve *curve, const uint8_t *pub_key,
                   const uint8_t *digest, const uint8_t *sign) {
  curve_point P, sG, R;
  bignum256 r, s, e;

  bn_read_be(sign, &r);
  bn_read_be(sign + 32, &s);

  // Signature is invalid if s >= n or r >= p.
  if (bn_is_zero(&r) ||
    bn_is_zero(&s) ||
    !bn_is_less(&r, &curve->prime) ||
    !bn_is_less(&s, &curve->order)) {
    return 1;
  }

  if (!ecdsa_read_pubkey(curve, pub_key, &P)) {
    return 2;
  }

  // Compute e
  calc_e(curve, &r, pub_key, digest, &e);

  // Compute R = sG - eP
  bn_cnegate(1, &e, &curve->order);
  bn_mod(&e, &curve->order);
  point_multiply(curve, &s, &curve->G, &sG);
  point_multiply(curve, &e, &P, &R);
  point_add(curve, &sG, &R);

  if (point_is_infinity(&R)) {
    return 3;
  }

  // Check r == Rx
  if (!bn_is_equal(&r, &R.x)) {
    return 4;
  }

  // Check Ry is a quadratic residue
  if (is_non_quad_residue(&R.y, &curve->prime)) {
    return 5;
  }

  return 0;
}
