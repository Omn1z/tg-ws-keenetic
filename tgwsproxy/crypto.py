"""MTProto obfuscation crypto: key derivation and re-encryption contexts.

A client sends a 64-byte init packet. From it we derive two AES-CTR keys
(decrypt-from-client and encrypt-to-client), authenticated by the proxy
secret. We also generate a fresh init packet for the upstream side and
derive its keys (decrypt-from-telegram and encrypt-to-telegram).

Bytes flowing through the bridge are decrypted with one key and immediately
re-encrypted with the other — payload is never seen in plaintext by the
proxy.
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .constants import (
    DC_IDX_POS,
    HANDSHAKE_LEN,
    IV_LEN,
    KEY_LEN,
    PREKEY_LEN,
    PROTO_TAG_ABRIDGED,
    PROTO_TAG_INTERMEDIATE,
    PROTO_TAG_PADDED_INTERMEDIATE,
    PROTO_TAG_POS,
    RESERVED_CONTINUE,
    RESERVED_FIRST_BYTES,
    RESERVED_STARTS,
    SKIP_LEN,
    ZERO_64,
)


def _aes_ctr(key: bytes, iv: bytes):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


@dataclass
class ClientHandshake:
    """What we extracted from the client's 64-byte init packet."""

    dc_id: int
    is_media: bool
    proto_tag: bytes
    prekey_iv: bytes  # 48 bytes, ready to derive client-side keys

    @property
    def dc_index(self) -> int:
        return -self.dc_id if self.is_media else self.dc_id

    @property
    def proto_int(self) -> int:
        if self.proto_tag == PROTO_TAG_ABRIDGED:
            return 0xEFEFEFEF
        if self.proto_tag == PROTO_TAG_INTERMEDIATE:
            return 0xEEEEEEEE
        return 0xDDDDDDDD


def parse_client_handshake(
    handshake: bytes, secret: bytes
) -> Optional[ClientHandshake]:
    """Try to authenticate and parse a client init packet."""
    prekey_iv = handshake[SKIP_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN]
    key = hashlib.sha256(prekey_iv[:PREKEY_LEN] + secret).digest()
    iv = prekey_iv[PREKEY_LEN:]

    decryptor = _aes_ctr(key, iv)
    decrypted = decryptor.update(handshake)

    proto_tag = decrypted[PROTO_TAG_POS : PROTO_TAG_POS + 4]
    if proto_tag not in (
        PROTO_TAG_ABRIDGED,
        PROTO_TAG_INTERMEDIATE,
        PROTO_TAG_PADDED_INTERMEDIATE,
    ):
        return None

    dc_signed = int.from_bytes(
        decrypted[DC_IDX_POS : DC_IDX_POS + 2], "little", signed=True
    )
    return ClientHandshake(
        dc_id=abs(dc_signed),
        is_media=dc_signed < 0,
        proto_tag=proto_tag,
        prekey_iv=prekey_iv,
    )


def generate_relay_handshake(proto_tag: bytes, dc_idx: int) -> bytes:
    """Build a fresh 64-byte handshake for upstream Telegram side."""
    while True:
        buf = bytearray(os.urandom(HANDSHAKE_LEN))
        if buf[0] in RESERVED_FIRST_BYTES:
            continue
        if bytes(buf[:4]) in RESERVED_STARTS:
            continue
        if bytes(buf[4:8]) == RESERVED_CONTINUE:
            continue
        break

    plain = bytes(buf)
    key = plain[SKIP_LEN : SKIP_LEN + PREKEY_LEN]
    iv = plain[SKIP_LEN + PREKEY_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN]

    encryptor = _aes_ctr(key, iv)
    dc_bytes = struct.pack("<h", dc_idx)
    tail_plain = proto_tag + dc_bytes + os.urandom(2)

    encrypted_full = encryptor.update(plain)
    keystream = bytes(encrypted_full[i] ^ plain[i] for i in range(56, 64))
    encrypted_tail = bytes(tail_plain[i] ^ keystream[i] for i in range(8))

    out = bytearray(plain)
    out[PROTO_TAG_POS:HANDSHAKE_LEN] = encrypted_tail
    return bytes(out)


@dataclass
class ReencryptionContext:
    """Holds the four AES-CTR streams used to re-encrypt bridge traffic."""

    client_decrypt: object  # decrypts bytes from the client
    client_encrypt: object  # encrypts bytes to the client
    upstream_encrypt: object  # encrypts bytes to Telegram
    upstream_decrypt: object  # decrypts bytes from Telegram


def build_context(
    client_prekey_iv: bytes, secret: bytes, relay_handshake: bytes
) -> ReencryptionContext:
    """Derive all four ciphers from a verified client handshake."""
    # Client side: authenticated by secret.
    client_dec_key = hashlib.sha256(
        client_prekey_iv[:PREKEY_LEN] + secret
    ).digest()
    client_dec_iv = client_prekey_iv[PREKEY_LEN:]

    reversed_prekey_iv = client_prekey_iv[::-1]
    client_enc_key = hashlib.sha256(
        reversed_prekey_iv[:PREKEY_LEN] + secret
    ).digest()
    client_enc_iv = reversed_prekey_iv[PREKEY_LEN:]

    client_decrypt = _aes_ctr(client_dec_key, client_dec_iv)
    client_encrypt = _aes_ctr(client_enc_key, client_enc_iv)

    # Fast-forward past the 64 init bytes that we already consumed.
    client_decrypt.update(ZERO_64)

    # Upstream side: raw obfuscation, no secret.
    relay_enc_key = relay_handshake[SKIP_LEN : SKIP_LEN + PREKEY_LEN]
    relay_enc_iv = relay_handshake[
        SKIP_LEN + PREKEY_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN
    ]
    relay_reversed = relay_handshake[
        SKIP_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN
    ][::-1]
    relay_dec_key = relay_reversed[:KEY_LEN]
    relay_dec_iv = relay_reversed[KEY_LEN:]

    upstream_encrypt = _aes_ctr(relay_enc_key, relay_enc_iv)
    upstream_decrypt = _aes_ctr(relay_dec_key, relay_dec_iv)
    upstream_encrypt.update(ZERO_64)

    return ReencryptionContext(
        client_decrypt=client_decrypt,
        client_encrypt=client_encrypt,
        upstream_encrypt=upstream_encrypt,
        upstream_decrypt=upstream_decrypt,
    )


def upstream_packet_decryptor(relay_handshake: bytes):
    """Return a fresh decryptor for the upstream encrypted stream.

    Used by MessageSplitter to peek packet lengths without disturbing the
    main upstream_encrypt stream.
    """
    key = relay_handshake[SKIP_LEN : SKIP_LEN + PREKEY_LEN]
    iv = relay_handshake[SKIP_LEN + PREKEY_LEN : SKIP_LEN + PREKEY_LEN + IV_LEN]
    dec = _aes_ctr(key, iv)
    dec.update(ZERO_64)
    return dec
