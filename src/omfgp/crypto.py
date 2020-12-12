"""Cryptographic functions"""

import sys

if sys.implementation.name == 'micropython':
    import ucryptolib
    # Electronic Code Book (ECB) mode of operation
    MODE_ECB = ucryptolib.MODE_ECB
    # Cipher Block Chaining (CBC) mode of operation
    MODE_CBC = ucryptolib.MODE_CBC

    class AES(ucryptolib.aes):
        # Block size in bits
        BLOCK_SIZE_BITS = 128
else:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    # Electronic Code Book (ECB) mode of operation
    MODE_ECB = 1
    # Cipher Block Chaining (CBC) mode of operation
    MODE_CBC = 2

    class AES:
        """AES block cipher"""

        # Block size in bits
        BLOCK_SIZE_BITS = 128

        def __init__(self, key, mode: int, IV=None):
            """Creates AES block cipher"""
            if mode == MODE_ECB:
                self._cipher = Cipher(algorithms.AES(key), modes.ECB(),
                                      backend=default_backend())
            elif mode == MODE_CBC:
                self._cipher = Cipher(algorithms.AES(key), modes.CBC(IV),
                                      backend=default_backend())
            else:
                raise ValueError("Unsupported mode of operation")

        def encrypt(self, in_buf):
            """Encrypts data"""
            encryptor = self._cipher.encryptor()
            return encryptor.update(in_buf) + encryptor.finalize()

        def decrypt(self, in_buf):
            """Decrypts data"""
            decryptor = self._cipher.decryptor()
            return decryptor.update(in_buf) + decryptor.finalize()


def xor_bytes(a, b):
    """Returns result of a XOR operation over two byte strings or arrays"""
    if len(a) != len(b):
        raise ValueError("Operands have different size")
    res = bytearray(a)
    for i, b in enumerate(b):
        res[i] ^= b
    return res


def _lshift1(data):
    """Shifts data in byte array or string by one bit left"""
    res = bytearray(data)
    if len(data):
        idx = 0
        for _ in range(len(data) - 1):
            res[idx] = (data[idx] << 1) & 0xff | (data[idx + 1] >> 7)
            idx += 1
        res[idx] = (data[idx] << 1) & 0xff
    return res


class CMAC:
    """CMAC implementation"""

    def __init__(self, cipher_class, key, tlen_bytes=None):
        """Creates an instance of CMAC algorithm"""
        self._ciph = cipher_class(key, MODE_ECB)
        assert self._ciph.BLOCK_SIZE_BITS % 8 == 0
        self._block_len = int(self._ciph.BLOCK_SIZE_BITS // 8)
        self._K1, self._K2 = self._derive_keys()
        if tlen_bytes is not None:
            if not (1 <= tlen_bytes <= self._block_len):
                raise ValueError("Incorrect MAC length")
        self.tlen_bytes = tlen_bytes

    def _derive_keys(self):
        """Derives K1 and K2 keys for CMAC algorithm"""
        # Select R constant
        if self._ciph.BLOCK_SIZE_BITS == 128:
            R = 15 * b'\x00' + b'\x87'  # 000...010000111
        elif self._ciph.BLOCK_SIZE_BITS == 64:
            R = 7 * b'\x00' + b'\x1b'  # 000...011011
        else:
            raise ValueError("Cipher has unsupported block size")

        # Derive K1 and K2
        L = self._ciph.encrypt(bytes(self._block_len))
        if L[0] & 0b10000000:  # Test MSB
            K1 = xor_bytes(_lshift1(L), R)
        else:
            K1 = _lshift1(L)
        if K1[0] & 0b10000000:  # Test MSB
            K2 = xor_bytes(_lshift1(K1), R)
        else:
            K2 = _lshift1(K1)
        return K1, K2

    def mac(self, msg):
        """Calculates MAC"""
        if len(msg) % self._block_len == 0:
            n_interim_blocks = int(len(msg) // self._block_len) - 1
        else:
            n_interim_blocks = int(len(msg) // self._block_len)

        # Process all complete blocks except for the last block
        idx = 0
        out_block = bytes(self._block_len)  # All zeroes
        for _ in range(n_interim_blocks):
            in_block = msg[idx: idx + self._block_len]
            out_block = self._ciph.encrypt(xor_bytes(in_block, out_block))
            idx += self._block_len

        # Process the final block
        if len(msg) - idx == self._block_len:  # Complete block
            in_block = xor_bytes(msg[idx:], self._K1)
        else:  # Incomplete block
            z = self._block_len - (len(msg) - idx) - 1
            in_block = xor_bytes(msg[idx:] + b'\x80' + z * b'\x00', self._K2)
        res = self._ciph.encrypt(xor_bytes(in_block, out_block))

        # Return MAC
        if self.tlen_bytes:
            return res[:self.tlen_bytes]
        return res
