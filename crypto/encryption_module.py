"""
crypto/encryption_module.py
----------------------------
Encryption Module (see report Section 5, module table row 2).

Real CP-ABE (Ciphertext-Policy Attribute-Based Encryption) relies on
pairing-based cryptography (e.g. the OpenABE / charm-crypto libraries).
Those require native pairing libraries that can't be installed in this
offline sandbox, so this module implements a policy-gated key-wrapping
scheme that reproduces CP-ABE's *access-control behaviour* using
standard primitives (AES-256-GCM + HKDF-SHA256), which are what's
available offline via Python's `cryptography` package:

  1. The file is encrypted once with a random per-file "data key" (AES-256-GCM).
  2. The data key itself is then wrapped ("policy-encrypted") using a key
     that is deterministically derived (HKDF) from the *sorted* list of
     attributes in the access policy plus a master secret held by the
     attribute authority.
  3. A user can only unwrap the data key -- and therefore decrypt the file --
     if they can present every attribute in the policy AND obtain the
     matching attribute-derived key material from the authority.

This preserves the property that matters for the demo: only requesters
whose attribute set satisfies the policy can decrypt, and revoking an
attribute (see blockchain/contract_simulator.py) removes that ability
going forward. Swapping this module for a real CP-ABE library
(e.g. `openabe`) in Phase 4 is a drop-in replacement -- the interface
(`encrypt_file` / `derive_user_key` / `decrypt_file`) would stay the same.
"""

import os
import json
import hashlib
import hmac
import struct

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except ImportError:
    # Fallback pure-Python implementation when cryptography is unavailable offline
    _SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5e, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    _RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def _rot_word(w):
        return ((w << 8) & 0xffffffff) | (w >> 24)

    def _sub_word(w):
        return (_SBOX[(w >> 24) & 0xff] << 24) | (_SBOX[(w >> 16) & 0xff] << 16) | (_SBOX[(w >> 8) & 0xff] << 8) | _SBOX[w & 0xff]

    def _aes256_key_expansion(key: bytes):
        w = [0] * 60
        for i in range(8):
            w[i] = struct.unpack(">I", key[4*i:4*i+4])[0]
        for i in range(8, 60):
            temp = w[i - 1]
            if i % 8 == 0:
                temp = _sub_word(_rot_word(temp)) ^ (_RCON[i // 8] << 24)
            elif i % 8 == 4:
                temp = _sub_word(temp)
            w[i] = w[i - 8] ^ temp
        return w

    def _xtime(a):
        return (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1)

    def _mix_column(c):
        a0, a1, a2, a3 = c
        t = a0 ^ a1 ^ a2 ^ a3
        u = a0
        c[0] ^= t ^ _xtime(a0 ^ a1)
        c[1] ^= t ^ _xtime(a1 ^ a2)
        c[2] ^= t ^ _xtime(a2 ^ a3)
        c[3] ^= t ^ _xtime(a3 ^ u)

    def _aes_encrypt_block(block: bytes, round_keys):
        state = list(block)
        for i in range(4):
            rk = round_keys[i]
            state[4*i]   ^= (rk >> 24) & 0xff
            state[4*i+1] ^= (rk >> 16) & 0xff
            state[4*i+2] ^= (rk >> 8) & 0xff
            state[4*i+3] ^= rk & 0xff
        for round_num in range(1, 14):
            for i in range(16):
                state[i] = _SBOX[state[i]]
            state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
            state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
            state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
            for c in range(4):
                col = [state[4*c], state[4*c+1], state[4*c+2], state[4*c+3]]
                _mix_column(col)
                state[4*c:4*c+4] = col
            for i in range(4):
                rk = round_keys[4*round_num + i]
                state[4*i]   ^= (rk >> 24) & 0xff
                state[4*i+1] ^= (rk >> 16) & 0xff
                state[4*i+2] ^= (rk >> 8) & 0xff
                state[4*i+3] ^= rk & 0xff
        for i in range(16):
            state[i] = _SBOX[state[i]]
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
        for i in range(4):
            rk = round_keys[56 + i]
            state[4*i]   ^= (rk >> 24) & 0xff
            state[4*i+1] ^= (rk >> 16) & 0xff
            state[4*i+2] ^= (rk >> 8) & 0xff
            state[4*i+3] ^= rk & 0xff
        return bytes(state)

    def _gf_mult(x: int, y: int) -> int:
        R = 0xe1000000000000000000000000000000
        z = 0
        v = x
        for i in range(127, -1, -1):
            if (y >> i) & 1:
                z ^= v
            if v & 1:
                v = (v >> 1) ^ R
            else:
                v = v >> 1
        return z

    def _ghash(h_int: int, data: bytes) -> int:
        y = 0
        for i in range(0, len(data), 16):
            block = data[i:i+16].ljust(16, b'\x00')
            x = int.from_bytes(block, 'big')
            y = _gf_mult(y ^ x, h_int)
        return y

    class AESGCM:
        def __init__(self, key: bytes):
            if len(key) != 32:
                raise ValueError("Key must be 32 bytes for AES-256")
            self.key = key
            self.round_keys = _aes256_key_expansion(key)
            h_bytes = _aes_encrypt_block(b'\x00' * 16, self.round_keys)
            self.h_int = int.from_bytes(h_bytes, 'big')

        @classmethod
        def generate_key(cls, bit_length=256):
            return os.urandom(bit_length // 8)

        def _ctr_crypt(self, cb: bytearray, data: bytes) -> bytes:
            out = bytearray(len(data))
            for i in range(0, len(data), 16):
                ctr_val = (int.from_bytes(cb[12:16], 'big') + 1) & 0xffffffff
                cb[12:16] = ctr_val.to_bytes(4, 'big')
                pad = _aes_encrypt_block(bytes(cb), self.round_keys)
                chunk = data[i:i+16]
                for j in range(len(chunk)):
                    out[i + j] = chunk[j] ^ pad[j]
            return bytes(out)

        def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes = None) -> bytes:
            if len(nonce) != 12:
                raise ValueError("Nonce must be 12 bytes")
            aad = associated_data or b""
            j0 = nonce + b"\x00\x00\x00\x01"
            cb = bytearray(j0)
            ct = self._ctr_crypt(cb, data)
            aad_pad = aad + b"\x00" * ((16 - (len(aad) % 16)) % 16)
            ct_pad = ct + b"\x00" * ((16 - (len(ct) % 16)) % 16)
            len_block = struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
            s = _ghash(self.h_int, aad_pad + ct_pad + len_block)
            s_bytes = s.to_bytes(16, 'big')
            j0_enc = _aes_encrypt_block(j0, self.round_keys)
            tag = bytes(a ^ b for a, b in zip(s_bytes, j0_enc))
            return ct + tag

        def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes = None) -> bytes:
            if len(data) < 16:
                raise ValueError("Ciphertext too short")
            ct = data[:-16]
            expected_tag = data[-16:]
            aad = associated_data or b""
            j0 = nonce + b"\x00\x00\x00\x01"
            aad_pad = aad + b"\x00" * ((16 - (len(aad) % 16)) % 16)
            ct_pad = ct + b"\x00" * ((16 - (len(ct) % 16)) % 16)
            len_block = struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
            s = _ghash(self.h_int, aad_pad + ct_pad + len_block)
            s_bytes = s.to_bytes(16, 'big')
            j0_enc = _aes_encrypt_block(j0, self.round_keys)
            tag = bytes(a ^ b for a, b in zip(s_bytes, j0_enc))
            if not hmac.compare_digest(tag, expected_tag):
                raise Exception("Authentication tag mismatch")
            cb = bytearray(j0)
            return self._ctr_crypt(cb, ct)

    class _HashesMock:
        class SHA256:
            pass

    hashes = _HashesMock()

    class HKDF:
        def __init__(self, algorithm, length, salt, info):
            self.length = length
            self.salt = salt if salt else b"\x00" * 32
            self.info = info

        def derive(self, ikm: bytes) -> bytes:
            prk = hmac.new(self.salt, ikm, hashlib.sha256).digest()
            t = b""
            okm = b""
            i = 1
            while len(okm) < self.length:
                t = hmac.new(prk, t + self.info + bytes([i]), hashlib.sha256).digest()
                okm += t
                i += 1
            return okm[:self.length]


class AttributeAuthority:
    """Issues attribute-derived key material to users who hold that attribute.
    Stand-in for the 'User & Identity Module' in the report."""

    def __init__(self, master_secret: bytes = None):
        self.master_secret = master_secret or os.urandom(32)
        self.user_attributes = {}  # user_id -> set(attributes)

    def issue_attribute(self, user_id: str, attribute: str):
        self.user_attributes.setdefault(user_id, set()).add(attribute)

    def revoke_attribute(self, user_id: str, attribute: str):
        self.user_attributes.get(user_id, set()).discard(attribute)

    def user_has_attribute(self, user_id: str, attribute: str) -> bool:
        return attribute in self.user_attributes.get(user_id, set())

    def _attribute_key_material(self, attribute: str) -> bytes:
        # Deterministic secret tied to one attribute + the authority's master secret.
        return hmac.new(self.master_secret, attribute.encode(), hashlib.sha256).digest()

    def derive_user_policy_key(self, user_id: str, policy: list[str]):
        """Returns the policy-derived key ONLY if the user holds every
        attribute in `policy` -- otherwise returns None (access denied
        at the crypto layer, independent of the smart contract check)."""
        for attr in policy:
            if not self.user_has_attribute(user_id, attr):
                return None
        return _derive_policy_key(policy, self._policy_secret(policy))

    def _policy_secret(self, policy: list[str]) -> bytes:
        # Combine each attribute's key material; order-independent (sorted).
        material = b"".join(self._attribute_key_material(a) for a in sorted(policy))
        return hashlib.sha256(material).digest()


def _derive_policy_key(policy: list[str], secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=("|".join(sorted(policy))).encode())
    return hkdf.derive(secret)


def encrypt_file(plaintext: bytes, policy: list[str], authority: AttributeAuthority):
    """Owner-side: encrypt file with a fresh data key, then wrap the data key
    under the policy. Returns a dict ready to be written to storage."""
    data_key = AESGCM.generate_key(bit_length=256)
    file_nonce = os.urandom(12)
    file_ct = AESGCM(data_key).encrypt(file_nonce, plaintext, None)

    policy_secret = authority._policy_secret(policy)
    policy_key = _derive_policy_key(policy, policy_secret)
    key_nonce = os.urandom(12)
    wrapped_key = AESGCM(policy_key).encrypt(key_nonce, data_key, None)

    return {
        "policy": policy,
        "file_nonce": file_nonce.hex(),
        "file_ciphertext": file_ct.hex(),
        "key_nonce": key_nonce.hex(),
        "wrapped_data_key": wrapped_key.hex(),
    }


def decrypt_file(envelope: dict, user_id: str, authority: AttributeAuthority) -> bytes:
    """User-side: attempt to unwrap the data key using the user's attributes,
    then decrypt the file. Raises PermissionError if the user's attributes
    don't satisfy the policy."""
    policy_key = authority.derive_user_policy_key(user_id, envelope["policy"])
    if policy_key is None:
        raise PermissionError(f"'{user_id}' does not satisfy policy {envelope['policy']}")

    data_key = AESGCM(policy_key).decrypt(
        bytes.fromhex(envelope["key_nonce"]),
        bytes.fromhex(envelope["wrapped_data_key"]),
        None,
    )
    plaintext = AESGCM(data_key).decrypt(
        bytes.fromhex(envelope["file_nonce"]),
        bytes.fromhex(envelope["file_ciphertext"]),
        None,
    )
    return plaintext


def envelope_to_json(envelope: dict) -> str:
    return json.dumps(envelope)


def envelope_from_json(s: str) -> dict:
    return json.loads(s)
