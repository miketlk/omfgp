"""Cryptographic functions"""

import sys
from .util import xor_bytes, lshift1_bytes, int_to_bytes_big_endian
from . import pyDes

try:
    from rng import get_random_bytes
    # Alias for random(n) function
    random = get_random_bytes
except:
    import os
    # Alias for random(n) function
    random = os.urandom

if sys.implementation.name == 'micropython':
    import ucryptolib
    # Electronic Code Book (ECB) mode of operation
    MODE_ECB = ucryptolib.MODE_ECB
    # Cipher Block Chaining (CBC) mode of operation
    MODE_CBC = ucryptolib.MODE_CBC

    class AES(ucryptolib.aes):
        # Block size in bytes
        BLOCK_N_BYTES = 128//8

        def add_padding(self, data: bytes):
            """Adds 0x80... padding according to NIST 800-38A"""
            return add_padding(data, self.BLOCK_N_BYTES)

        def remove_padding(self, data: bytes):
            """Removes 0x80... padding according to NIST 800-38A"""
            return remove_padding(data, self.BLOCK_N_BYTES)

else:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    # Electronic Code Book (ECB) mode of operation
    MODE_ECB = 1
    # Cipher Block Chaining (CBC) mode of operation
    MODE_CBC = 2

    class AES:
        """AES block cipher"""

        # Block size in bytes
        BLOCK_N_BYTES = 128//8

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

        def add_padding(self, data: bytes):
            """Adds 0x80... padding according to NIST 800-38A"""
            return add_padding(data, self.BLOCK_N_BYTES)

        def remove_padding(self, data: bytes):
            """Removes 0x80... padding according to NIST 800-38A"""
            return remove_padding(data, self.BLOCK_N_BYTES)


class DES:
    """DES / Triple DES block cipher"""

    # Block size in bytes
    BLOCK_N_BYTES = 64//8

    def __init__(self, key, mode: int, IV=None):
        """Creates DES block cipher"""
        mode = {MODE_ECB: pyDes.ECB, MODE_CBC: pyDes.CBC}.get(mode)
        if mode is None:
            raise ValueError("Unsupported mode of operation")

        if len(key) == 8:
            self._cipher = pyDes.des(key, mode, IV)
        elif len(key) in (16, 24):
            self._cipher = pyDes.triple_des(key, mode, IV)
        else:
            raise ValueError("Invalid key length")

    def encrypt(self, in_buf):
        """Encrypts data"""
        return self._cipher.encrypt(in_buf)

    def decrypt(self, in_buf):
        """Decrypts data"""
        return self._cipher.decrypt(in_buf)

    def add_padding(self, data: bytes):
        """Adds 0x80... padding according to NIST 800-38A"""
        return add_padding(data, self.BLOCK_N_BYTES)

    def remove_padding(self, data: bytes):
        """Removes 0x80... padding according to NIST 800-38A"""
        return remove_padding(data, self.BLOCK_N_BYTES)

    @classmethod
    def cbc_mac(cls, key: bytes, msg: bytes, IV=None) -> bytes:
        """Calculate DES CBC-MAC"""
        if not len(key) in (8, 16, 24):
            raise ValueError("Invalid key length")
        tdes_ecb = cls(key, MODE_ECB)
        block_n_bytes = cls.BLOCK_N_BYTES
        mac = IV if IV else block_n_bytes * b'\0'
        msg_blocks = tdes_ecb.add_padding(msg)
        for idx in range(0, len(msg_blocks), block_n_bytes):
            in_block = msg_blocks[idx: idx + block_n_bytes]
            mac = tdes_ecb.encrypt(xor_bytes(mac, in_block))
        return mac

    @classmethod
    def cbc_mac_single(cls, key: bytes, msg: bytes, IV=None) -> bytes:
        """Calculate single DES CBC-MAC with final Triple DES CBC-MAC"""
        if not len(key) in (16, 24):
            raise ValueError("Invalid key length")
        des_ecb = cls(key[:8], MODE_ECB)
        tdes_ecb = cls(key, MODE_ECB)
        block_n_bytes = cls.BLOCK_N_BYTES

        mac = IV if IV else block_n_bytes * b'\0'
        msg_blocks = des_ecb.add_padding(msg)
        final_block_idx = len(msg_blocks) - block_n_bytes
        for idx in range(0, len(msg_blocks), block_n_bytes):
            in_block = msg_blocks[idx: idx + block_n_bytes]
            if idx < final_block_idx:
                mac = des_ecb.encrypt(xor_bytes(mac, in_block))
            else:
                mac = tdes_ecb.encrypt(xor_bytes(mac, in_block))  # Final block
        return mac


class PRF:
    """Base class for algorithms usable as a pseudo-random function for KBKDF
    """

    def prf(self, x):
        """Invokes a pseudo-random function with a key from PRF instance"""
        raise NotImplementedError()

    @property
    def prf_len_bytes(self):
        """Returns the length of the output of the PRF in bytes"""
        raise NotImplementedError()


class CMAC(PRF):
    """Block cipher-based MAC algorithm (NIST SP 800-38B)"""

    def __init__(self, cipher_class, key, tlen_bytes=None):
        """Creates an instance of CMAC algorithm"""
        self._ciph = cipher_class(key, MODE_ECB)
        self._block_len = int(self._ciph.BLOCK_N_BYTES)
        self._K1, self._K2 = self._derive_keys()
        self.tlen_bytes = self._block_len if tlen_bytes is None else tlen_bytes
        if not (1 <= self.tlen_bytes <= self._block_len):
            raise ValueError("Incorrect MAC length")

    def _derive_keys(self):
        """Derives K1 and K2 keys for CMAC algorithm"""
        # Select R constant
        if self._ciph.BLOCK_N_BYTES == 16:  # 128 bit
            R = 15 * b'\x00' + b'\x87'  # 000...010000111
        elif self._ciph.BLOCK_N_BYTES == 8:  # 64 bit
            R = 7 * b'\x00' + b'\x1b'  # 000...011011
        else:
            raise ValueError("Cipher has unsupported block size")

        # Derive K1 and K2
        L = self._ciph.encrypt(bytes(self._block_len))
        if L[0] & 0b10000000:  # Test MSB
            K1 = xor_bytes(lshift1_bytes(L), R)
        else:
            K1 = lshift1_bytes(L)
        if K1[0] & 0b10000000:  # Test MSB
            K2 = xor_bytes(lshift1_bytes(K1), R)
        else:
            K2 = lshift1_bytes(K1)
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

        # Process the final block and return MAC
        if len(msg) - idx == self._block_len:  # Complete block
            in_block = xor_bytes(msg[idx:], self._K1)
        else:  # Incomplete block
            z = self._block_len - (len(msg) - idx) - 1
            in_block = xor_bytes(msg[idx:] + b'\x80' + z * b'\x00', self._K2)
        res = self._ciph.encrypt(xor_bytes(in_block, out_block))
        return res[:self.tlen_bytes]

    def prf(self, x):
        """Invokes a pseudo-random function with a key from PRF instance"""
        return self.mac(x)

    @property
    def prf_len_bytes(self):
        """Returns the length of the output of the PRF in bytes"""
        return self.tlen_bytes


class KBKDF:
    """Key-based key derivation function (NIST SP 800-108)"""

    # Configures KDF in counter mode
    MODE_COUNTER = 1

    # Counter before fixed input data
    LOC_BEFORE_FIXED = 1
    # Counter in middle of fixed input data before context
    LOC_MIDDLE_FIXED = 2
    # Counter after fixed input data
    LOC_AFTER_FIXED = 3

    def __init__(self, prf_inst: PRF, ctrlen_bytes, ctr_loc: int, mode: int):
        """Creates an instance of KDF"""
        if mode == KBKDF.MODE_COUNTER:
            assert prf_inst.prf_len_bytes >= 1
            self._prf_inst = prf_inst
            self._ctrlen_bytes = ctrlen_bytes
            self._ctr_loc = ctr_loc
            self._derive_fn = self._derive_in_counter_mode
        else:
            raise NotImplementedError("Mode not supported")

    def _make_input_block(self, ctr, data1, data2):
        """Composes input block for PRF"""
        ctr_bytes = int_to_bytes_big_endian(ctr, self._ctrlen_bytes)
        if self._ctr_loc == KBKDF.LOC_BEFORE_FIXED:
            return ctr_bytes + data1 + data2
        elif self._ctr_loc == KBKDF.LOC_MIDDLE_FIXED:
            return data1 + ctr_bytes + data2
        elif self._ctr_loc == KBKDF.LOC_AFTER_FIXED:
            return data1 + data2 + ctr_bytes
        else:
            raise ValueError("Invalid counter location")

    def _derive_in_counter_mode(self, len_bytes, data1, data2=b'', iv=None):
        """Derives key material"""
        if len_bytes == 0:
            return b''
        n_blocks = -(len_bytes // -self._prf_inst.prf_len_bytes)
        if n_blocks > (256 ** self._ctrlen_bytes) - 1:
            raise ValueError("Counter overflow")

        result = bytearray()
        ctr = 1
        len_remainder = len_bytes % self._prf_inst.prf_len_bytes
        for _ in range(n_blocks):
            in_block = self._make_input_block(ctr, data1, data2)
            if ctr == n_blocks and len_remainder:
                result += self._prf_inst.prf(in_block)[:len_remainder]
            else:
                result += self._prf_inst.prf(in_block)
            ctr += 1

        return result

    def derive(self, len_bytes, data1, data2=b'', iv=None):
        return self._derive_fn(len_bytes, data1, data2, iv)


def add_padding(data: bytes, block_n_bytes: int) -> bytes:
    """Adds 0x80... padding according to NIST 800-38A"""
    res = data + b'\x80'
    len_remainder = len(res) % block_n_bytes
    if len_remainder != 0:
        res += b'\0' * (block_n_bytes - len_remainder)
    return res


def remove_padding(data: bytes, block_n_bytes: int) -> bytes:
    """Removes 0x80... padding according to NIST 800-38A"""
    if len(data) % block_n_bytes != 0:
        raise ValueError("Invalid data")

    for i in range(len(data) - 1, -1, -1):
        if data[i] == 0x80:
            return data[:i]
        elif data[i] != 0x00:
            raise ValueError("Invalid padding")
    raise ValueError("Invalid padding")
