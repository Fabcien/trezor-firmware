/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2025 The Bitcoin ABC developers
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

void fsm_msgEcashSignStake(const EcashSignStake *msg) {
  (void)msg;

  RESP_INIT(EcashStakeSignature);

  CHECK_INITIALIZED

  CHECK_PIN

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);

  if (!node) return;

  // Show the stake data for confirmation
  const char **txid_str = split_message_hex(msg->txid.bytes, msg->txid.size);
  layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Continue"), NULL,
                    _("TxId:"), txid_str[0], txid_str[1], txid_str[2],
                    txid_str[3], NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  char index_str[21] = {0};
  bn_format_amount(msg->index, NULL, NULL, 0, index_str, sizeof(index_str));
  char amount_str[32] = {0};
  bn_format_amount(msg->amount, NULL, "XEC", 2, amount_str, sizeof(amount_str));
  layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Continue"), NULL,
                    _("Output index:"), index_str, _("Amount:"), amount_str,
                    NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  char height_str[21] = {0};
  bn_format_amount(msg->height, NULL, NULL, 0, height_str, sizeof(height_str));
  char is_coinbase_str[4] = {0};
  if (msg->is_coinbase) {
    memcpy(is_coinbase_str, "Yes", 3);
  } else {
    memcpy(is_coinbase_str, "No", 2);
  }
  layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Continue"), NULL,
                    _("Block height:"), height_str, _("Coinbase?:"),
                    is_coinbase_str, NULL, NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  char expiration_str[32] = {0};
  bn_format_amount(msg->expiration_time, NULL, NULL, 0, expiration_str,
                   sizeof(expiration_str));
  layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Continue"), NULL,
                    _("Expiration time:"), expiration_str, NULL, NULL, NULL,
                    NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  // We print up to 24 chars per page so the display is nice for both 33 and 65
  // bytes pubkeys.
  uint8_t num_pages = 1 + msg->master_pubkey.size / 24;
  uint8_t master_pubkey_remaining_size = msg->master_pubkey.size;
  for (int page = 0; page < num_pages; page++) {
    char footer[19] = {0};
    for (int c = 0; c < 3; c++) {
      footer[c] = page < (num_pages - 1) ? '.' : ' ';
    }
    for (int c = 3; c < 12; c++) {
      footer[c] = ' ';
    }
    footer[12] = '(';
    footer[13] = 0x30 + page + 1;
    footer[14] = '/';
    footer[15] = 0x30 + num_pages;
    footer[16] = ')';
    footer[17] = '\0';

    const char **master_pubkey_str = split_message_hex(
        msg->master_pubkey.bytes + 24 * page,
        master_pubkey_remaining_size > 24 ? 24 : master_pubkey_remaining_size);
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Continue"), NULL,
                      _("Master public key:"), master_pubkey_str[0],
                      master_pubkey_str[1], master_pubkey_str[2], footer, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      layoutHome();
      return;
    }

    master_pubkey_remaining_size -= 24;
  }

  layoutProgressSwipe(_("Signing"), 0);

  // Extract the public key
  if (hdnode_fill_public_key(node) != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    _("Failed to derive public key"));
    layoutHome();
    return;
  }

  // Hash the stake data
  uint8_t stake_commitment[HASHER_DIGEST_LENGTH] = {0};
  Hasher commitment_hasher = {0};
  hasher_Init(&commitment_hasher, HASHER_SHA2D);
  hasher_Update(&commitment_hasher, (const uint8_t *)&msg->expiration_time, 8);
  uint8_t master_pubkey_varint[5] = {0};
  uint32_t l = ser_length(msg->master_pubkey.size, master_pubkey_varint);
  hasher_Update(&commitment_hasher, master_pubkey_varint, l);
  hasher_Update(&commitment_hasher, msg->master_pubkey.bytes,
                msg->master_pubkey.size);
  hasher_Final(&commitment_hasher, stake_commitment);

  uint8_t stake_hashed[HASHER_DIGEST_LENGTH] = {0};
  Hasher stake_hasher = {0};
  hasher_Init(&stake_hasher, HASHER_SHA2D);
  hasher_Update(&stake_hasher, stake_commitment, HASHER_DIGEST_LENGTH);
  // Reverse the txid bytes order
  uint8_t txid_reversed[msg->txid.size];
  for (uint8_t i = 0; i < msg->txid.size; i++) {
    txid_reversed[i] = msg->txid.bytes[msg->txid.size - 1 - i];
  }
  hasher_Update(&stake_hasher, txid_reversed, msg->txid.size);
  hasher_Update(&stake_hasher, (const uint8_t *)&msg->index, 4);
  hasher_Update(&stake_hasher, (const uint8_t *)&msg->amount, 8);
  uint32_t height_coinbase = msg->height << 1 | (uint32_t)msg->is_coinbase;
  hasher_Update(&stake_hasher, (const uint8_t *)&height_coinbase, 4);
  uint8_t pubkey_varint[5] = {0};
  const uint32_t pubkey_size = 33;
  l = ser_length(pubkey_size, pubkey_varint);
  hasher_Update(&stake_hasher, pubkey_varint, l);
  hasher_Update(&stake_hasher, node->public_key, pubkey_size);
  hasher_Final(&stake_hasher, stake_hashed);

  // Sign with schnorr and fill the response message
  resp->signature.size = 64;
  if (schnorr_sign_digest(&secp256k1, node->private_key, stake_hashed,
                          resp->signature.bytes)) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    _("Stake signature failed"));
    layoutHome();
    return;
  }

  resp->pubkey.size = pubkey_size;
  memcpy(resp->pubkey.bytes, node->public_key, pubkey_size);
  msg_write(MessageType_MessageType_EcashStakeSignature, resp);

  layoutHome();
}
