"""AES-128 Symmetric Block Cipher and CBC Mode implementation from first principles.

Compliant with NIST FIPS PUB 197 and SP 800-38A.
Does not use any external cryptographic libraries.
"""

from typing import List

# Reduction polynomial for GF(2^8): m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
IRREDUCIBLE_POLY = 0x11B


def xtime(b: int) -> int:
    """Multiply a byte by x (i.e. {02}) in GF(2^8)."""
    return ((b << 1) ^ IRREDUCIBLE_POLY) if (b & 0x80) else (b << 1)


def gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8) modulo m(x)."""
    res = 0
    curr_a = a
    curr_b = b
    while curr_b > 0:
        if curr_b & 1:
            res ^= curr_a
        curr_a = xtime(curr_a)
        curr_b >>= 1
    return res


def gf_inv(byte_val: int) -> int:
    """Compute multiplicative inverse in GF(2^8). 0 is mapped to 0."""
    if byte_val == 0:
        return 0
    # In GF(2^8), a^255 = 1, so a^(-1) = a^254
    res = 1
    base = byte_val
    exponent = 254
    while exponent > 0:
        if exponent & 1:
            res = gf_mul(res, base)
        base = gf_mul(base, base)
        exponent >>= 1
    return res


def affine_transform(byte_val: int) -> int:
    """Apply the AES affine transformation over GF(2)."""
    transformed = 0
    for i in range(8):
        bit = (
            ((byte_val >> i) & 1)
            ^ ((byte_val >> ((i + 4) % 8)) & 1)
            ^ ((byte_val >> ((i + 5) % 8)) & 1)
            ^ ((byte_val >> ((i + 6) % 8)) & 1)
            ^ ((byte_val >> ((i + 7) % 8)) & 1)
            ^ ((0x63 >> i) & 1)
        )
        transformed |= (bit << i)
    return transformed


def _build_sbox() -> tuple[list[int], list[int]]:
    """Generate the AES S-box and Inverse S-box from first principles."""
    forward_sbox = [affine_transform(gf_inv(i)) for i in range(256)]
    inverse_sbox = [0] * 256
    for i, val in enumerate(forward_sbox):
        inverse_sbox[val] = i
    return forward_sbox, inverse_sbox


# Precomputed tables generated from mathematical first principles on module load
S_BOX, INV_S_BOX = _build_sbox()

# Round constants Rcon for AES-128 (10 rounds)
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def bytes_to_state(block: bytes) -> List[List[int]]:
    """Convert a 16-byte block into a 4x4 State matrix in column-major order."""
    if len(block) != 16:
        raise ValueError("Block size must be exactly 16 bytes")
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_bytes(state: List[List[int]]) -> bytes:
    """Convert a 4x4 State matrix into a 16-byte block in column-major order."""
    return bytes(state[r][c] for c in range(4) for r in range(4))


def sub_bytes(state: List[List[int]]) -> None:
    """Substitute each byte of the state using the S-box in-place."""
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]


def inv_sub_bytes(state: List[List[int]]) -> None:
    """Substitute each byte of the state using the Inverse S-box in-place."""
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]


def shift_rows(state: List[List[int]]) -> None:
    """Cyclically shift rows to the left in-place."""
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def inv_shift_rows(state: List[List[int]]) -> None:
    """Cyclically shift rows to the right in-place."""
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]


def mix_columns(state: List[List[int]]) -> None:
    """Multiply columns of the state by fixed polynomial in GF(2^8) in-place."""
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3
        state[1][c] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3
        state[2][c] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3)
        state[3][c] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3)


def inv_mix_columns(state: List[List[int]]) -> None:
    """Multiply columns of the state by inverse polynomial in GF(2^8) in-place."""
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = (
            gf_mul(0x0E, s0) ^ gf_mul(0x0B, s1) ^ gf_mul(0x0D, s2) ^ gf_mul(0x09, s3)
        )
        state[1][c] = (
            gf_mul(0x09, s0) ^ gf_mul(0x0E, s1) ^ gf_mul(0x0B, s2) ^ gf_mul(0x0D, s3)
        )
        state[2][c] = (
            gf_mul(0x0D, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0E, s2) ^ gf_mul(0x0B, s3)
        )
        state[3][c] = (
            gf_mul(0x0B, s0) ^ gf_mul(0x0D, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0E, s3)
        )


def add_round_key(state: List[List[int]], round_key_block: bytes) -> None:
    """Combine the state with a 16-byte round key using XOR in-place."""
    rk_state = bytes_to_state(round_key_block)
    for r in range(4):
        for c in range(4):
            state[r][c] ^= rk_state[r][c]


def rot_word(word: list[int]) -> list[int]:
    """Perform cyclic left shift of a 4-byte word."""
    return word[1:] + word[:1]


def sub_word(word: list[int]) -> list[int]:
    """Apply S-box to each byte in a 4-byte word."""
    return [S_BOX[b] for b in word]


def key_expansion(key: bytes) -> List[bytes]:
    """Expand a 128-bit (16-byte) key into 11 round keys of 16 bytes each."""
    if len(key) != 16:
        raise ValueError("AES-128 requires exactly 16 bytes (128 bits) key")

    words: list[list[int]] = []
    for i in range(4):
        words.append(list(key[4 * i : 4 * i + 4]))

    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[(i // 4) - 1]

        new_word = [words[i - 4][b] ^ temp[b] for b in range(4)]
        words.append(new_word)

    round_keys: List[bytes] = []
    for r in range(11):
        rk_bytes = bytearray()
        for c in range(4):
            rk_bytes.extend(words[r * 4 + c])
        round_keys.append(bytes(rk_bytes))

    return round_keys


def encrypt_block(block: bytes, round_keys: List[bytes]) -> bytes:
    """Encrypt a single 16-byte block with AES-128."""
    if len(block) != 16:
        raise ValueError("AES operates on 16-byte blocks")

    state = bytes_to_state(block)

    # Initial round
    add_round_key(state, round_keys[0])

    # Rounds 1 through 9
    for r in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])

    # Final round (round 10, no MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])

    return state_to_bytes(state)


def decrypt_block(block: bytes, round_keys: List[bytes]) -> bytes:
    """Decrypt a single 16-byte block with AES-128."""
    if len(block) != 16:
        raise ValueError("AES operates on 16-byte blocks")

    state = bytes_to_state(block)

    # Initial round
    add_round_key(state, round_keys[10])

    # Inverse rounds 9 down to 1
    for r in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[r])
        inv_mix_columns(state)

    # Final inverse round (round 0, no InvMixColumns)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return state_to_bytes(state)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Apply PKCS#7 padding to align data length to a multiple of block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove and validate PKCS#7 padding."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding byte value")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding pattern")
    return data[:-pad_len]


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt plaintext using AES-128 in CBC mode with PKCS#7 padding."""
    if len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes")

    round_keys = key_expansion(key)
    padded = pkcs7_pad(plaintext, 16)
    ciphertext = bytearray()
    prev = iv

    for i in range(0, len(padded), 16):
        block = padded[i : i + 16]
        xored = bytes(b ^ p for b, p in zip(block, prev))
        encrypted_block = encrypt_block(xored, round_keys)
        ciphertext.extend(encrypted_block)
        prev = encrypted_block

    return bytes(ciphertext)


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt ciphertext using AES-128 in CBC mode and remove PKCS#7 padding."""
    if len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes")
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a non-zero multiple of 16 bytes")

    round_keys = key_expansion(key)
    decrypted_blocks = bytearray()
    prev = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i : i + 16]
        decrypted_raw = decrypt_block(block, round_keys)
        xored = bytes(d ^ p for d, p in zip(decrypted_raw, prev))
        decrypted_blocks.extend(xored)
        prev = block

    return pkcs7_unpad(bytes(decrypted_blocks), 16)
