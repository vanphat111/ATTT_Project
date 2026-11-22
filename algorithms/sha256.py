MASK_32: int = 0xFFFFFFFF

INITIAL_HASH_VALUES: tuple[int, ...] = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

ROUND_CONSTANTS: tuple[int, ...] = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK_32


def shr(x: int, n: int) -> int:
    return (x & MASK_32) >> n


def ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ ((~x & MASK_32) & z)


def maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def upper_sigma0(x: int) -> int:
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def upper_sigma1(x: int) -> int:
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def lower_sigma0(x: int) -> int:
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def lower_sigma1(x: int) -> int:
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


def to_bytes(data: bytes | bytearray | str) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    raise TypeError("Input must be str, bytes, or bytearray")


def pad_message(message: bytes) -> bytes:
    bit_length = len(message) * 8
    padded = bytearray(message)
    padded.append(0x80)
    while (len(padded) % 64) != 56:
        padded.append(0x00)
    padded.extend(bit_length.to_bytes(8, byteorder="big"))
    return bytes(padded)


def parse_blocks(padded_message: bytes) -> list[list[int]]:
    blocks: list[list[int]] = []
    for i in range(0, len(padded_message), 64):
        chunk = padded_message[i : i + 64]
        words = [
            int.from_bytes(chunk[j : j + 4], byteorder="big")
            for j in range(0, 64, 4)
        ]
        blocks.append(words)
    return blocks


def generate_message_schedule(block: list[int]) -> list[int]:
    schedule = list(block)
    for t in range(16, 64):
        word = (
            lower_sigma1(schedule[t - 2])
            + schedule[t - 7]
            + lower_sigma0(schedule[t - 15])
            + schedule[t - 16]
        ) & MASK_32
        schedule.append(word)
    return schedule


def compress_block(hash_state: list[int], schedule: list[int]) -> list[int]:
    a, b, c, d, e, f, g, h = hash_state
    for t in range(64):
        t1 = (
            h
            + upper_sigma1(e)
            + ch(e, f, g)
            + ROUND_CONSTANTS[t]
            + schedule[t]
        ) & MASK_32
        t2 = (upper_sigma0(a) + maj(a, b, c)) & MASK_32

        h = g
        g = f
        f = e
        e = (d + t1) & MASK_32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK_32

    return [
        (hash_state[0] + a) & MASK_32,
        (hash_state[1] + b) & MASK_32,
        (hash_state[2] + c) & MASK_32,
        (hash_state[3] + d) & MASK_32,
        (hash_state[4] + e) & MASK_32,
        (hash_state[5] + f) & MASK_32,
        (hash_state[6] + g) & MASK_32,
        (hash_state[7] + h) & MASK_32,
    ]


def sha256_bytes(data: bytes | bytearray | str) -> bytes:
    message = to_bytes(data)
    padded = pad_message(message)
    blocks = parse_blocks(padded)
    hash_state = list(INITIAL_HASH_VALUES)

    for block in blocks:
        schedule = generate_message_schedule(block)
        hash_state = compress_block(hash_state, schedule)

    return b"".join(word.to_bytes(4, byteorder="big") for word in hash_state)


def sha256_hex(data: bytes | bytearray | str) -> str:
    return sha256_bytes(data).hex()