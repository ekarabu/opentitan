from math import log
from operator import xor
from copy import deepcopy
from functools import reduce
from binascii import hexlify

# The Keccak-f round constants.
RoundConstants = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]

RotationConstants = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
]

Masks = [(1 << i) - 1 for i in range(65)]


def bits2bytes(x):
    return (int(x) + 7) // 8


def rol(value, left, bits):
    """
    Circularly rotate 'value' to the left,
    treating it as a quantity of the given size in bits.
    """
    top = value >> (bits - left)
    bot = (value & Masks[bits - left]) << left
    return bot | top


def ror(value, right, bits):
    """
    Circularly rotate 'value' to the right,
    treating it as a quantity of the given size in bits.
    """
    top = value >> right
    bot = (value & Masks[right]) << (bits - right)
    return bot | top


def keccak_f(state):
    """
    This is Keccak-f permutation.  It operates on and
    mutates the passed-in KeccakState.  It returns nothing.
    """

    def keccak_round(a, rc):
        w, h = state.W, state.H
        rangew, rangeh = state.rangeW, state.rangeH
        lanew = state.lanew
        zero = state.zero

        # theta
        c = [reduce(xor, a[x]) for x in rangew]
        d = [0] * w
        for x in rangew:
            d[x] = c[(x - 1) % w] ^ rol(c[(x + 1) % w], 1, lanew)
            for y in rangeh:
                a[x][y] ^= d[x]

        # rho and pi
        b = zero()
        for x in rangew:
            for y in rangeh:
                b[y % w][(2 * x + 3 * y) % h] = rol(
                    a[x][y], RotationConstants[y][x], lanew
                )

        # chi
        for x in rangew:
            for y in rangeh:
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % w][y]) & b[(x + 2) % w][y])

        # iota
        a[0][0] ^= rc

    nr = 12 + 2 * int(log(state.lanew, 2))

    for ir in range(nr):
        keccak_round(state.s, RoundConstants[ir])


class KeccakState:
    """
    A keccak state container.

    The state is stored as a 5x5 table of integers.
    """

    W = 5
    H = 5

    rangeW = range(W)
    rangeH = range(H)

    @staticmethod
    def zero():
        """
        Returns an zero state table.
        """
        return [[0] * KeccakState.W for _ in KeccakState.rangeH]

    @staticmethod
    def format(st):
        """
        Formats the given state as hex, in natural byte order.
        """
        rows = []

        def fmt(stx):
            return "%016x" % stx

        for y in KeccakState.rangeH:
            row = []
            for x in KeccakState.rangeW:
                row.append(fmt(st[x][y]))
            rows.append(" ".join(row))
        return "\n".join(rows)

    @staticmethod
    def lane2bytes(s, w):
        """
        Converts the lane s to a sequence of byte values,
        assuming a lane is w bits.
        """
        o = []
        for b in range(0, w, 8):
            o.append((s >> b) & 0xFF)
        return o

    @staticmethod
    def bytes2lane(bb):
        """
        Converts a sequence of byte values to a lane.
        """
        r = 0
        for b in reversed(bb):
            r = r << 8 | b
        return r

    @staticmethod
    def ilist2bytes(bb):
        """
        Converts a sequence of byte values to a bytestring.
        """
        return bytes(bb)

    @staticmethod
    def bytes2ilist(ss):
        """
        Converts a string or bytestring to a sequence of byte values.
        """
        return map(ord, ss) if isinstance(ss, str) else list(ss)

    def __init__(self, bitrate, b):
        self.bitrate = bitrate
        self.b = b

        # only byte-aligned
        assert self.bitrate % 8 == 0
        self.bitrate_bytes = bits2bytes(self.bitrate)

        assert self.b % 25 == 0
        self.lanew = self.b // 25

        self.s = KeccakState.zero()

    def __str__(self):
        return KeccakState.format(self.s)

    def absorb(self, bb):
        """
        Mixes in the given bitrate-length string to the state.
        """
        assert len(bb) == self.bitrate_bytes

        bb += [0] * bits2bytes(self.b - self.bitrate)
        i = 0

        for y in self.rangeH:
            for x in self.rangeW:
                self.s[x][y] ^= KeccakState.bytes2lane(bb[i : i + 8])
                i += 8

    def squeeze(self):
        """
        Returns the bitrate-length prefix of the state to be output.
        """
        return self.get_bytes()[: self.bitrate_bytes]

    def get_bytes(self):
        """
        Convert whole state to a byte string.
        """
        out = [0] * bits2bytes(self.b)
        i = 0
        for y in self.rangeH:
            for x in self.rangeW:
                v = KeccakState.lane2bytes(self.s[x][y], self.lanew)
                out[i : i + 8] = v
                i += 8
        return out

    def set_bytes(self, bb):
        """
        Set whole state from byte string, which is assumed
        to be the correct length.
        """
        i = 0
        for y in self.rangeH:
            for x in self.rangeW:
                self.s[x][y] = KeccakState.bytes2lane(bb[i : i + 8])
                i += 8



SHAKE128_RATE = 168

def CSHAKE_imp(hex_message):
    # Create customization (domain separation) string
    sep = bytearray(SHAKE128_RATE)
    sep[0] = 0x01
    sep[1] = 0xA8
    sep[2] = 0x01
    sep[3] = 0x00
    sep[4] = 0x01
    sep[5] = 0x38
    sep[6] = 0x4C
    sep[7] = 0x43
    sep[8] = 0x5F
    sep[9] = 0x43
    sep[10] = 0x54
    sep[11] = 0x52
    sep[12] = 0x4C
    
    # Convert bytearray to list for compatibility with absorb
    sep_list = list(sep)
    
    # Absorb the customization string
    state = KeccakState(SHAKE128_RATE * 8, 1600)
    state.absorb(sep_list)
    # Perform Keccak permutation
    keccak_f(state)
    # for x in state.s:
    #     print([hex(v) for v in x])
    
    # Convert the hex_message to a bytearray
    message = bytearray.fromhex(f"{hex_message:032x}")
    mlen = len(message)
    r = 168

    assert isinstance(state, KeccakState), "State must be an instance of KeccakState"
    assert isinstance(message, (bytes, bytearray)), "Message must be bytes or bytearray"
    
    # Process full blocks of message
    while mlen >= r:
        idx = 0  # Initialize index for message chunks
        for i in range(5):  # Iterate over rows
            for j in range(5):  # Iterate over columns
                if idx * 8 >= r:  # Ensure we only process up to r bytes
                    break
                chunk = message[8 * idx : 8 * (idx + 1)]
                state.s[j][i] ^= int.from_bytes(chunk, byteorder="little")
                idx += 1
        keccak_f(state)  # Perform Keccak permutation
        mlen -= r
        message = message[r:]

    # Process the remaining message block with padding
    t = bytearray(200)
    for i in range(200):
        t[i] = 0x00
    for i in range(len(message)):
        t[i] = message[i]
    t[len(message)] = 0x04
    t[r - 1] |= 0x80

    idx = 0
    for i in range(5):  # Iterate over rows
        for j in range(5):  # Iterate over columns
            chunk = t[8 * idx : 8 * (idx + 1)]
            state.s[j][i] ^= int.from_bytes(chunk, byteorder="little")
            idx += 1
    
    print("==========") 
    keccak_f(state)
    # for x in state.s:
    #     print([hex(v) for v in x])
    # Combine the hex values into a single string
    print(f"{state.s[1][0]:x}{state.s[0][0]:x}")