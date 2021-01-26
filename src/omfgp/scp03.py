"""Secure Channel Protocol version 03"""

from io import BytesIO
from binascii import hexlify
from struct import pack

from . import status
from . import card
from .commands import *
from . import crypto
from .scp import *
from .util import int_to_bytes_big_endian

# Cryptogram size in bits
CRYPTOGRAM_N_BITS = 0x0040
# Challenge size in bits
CHALLENGE_N_BITS = 0x0040
# Size of MAC in bytes
MAC_N_BYTES = 8
# Number of bytes in ecryption counter used to produce ICV
CTR_N_BYTES = 16
# Constant value of the class byte used for MAC calculation (0x84)
MAC_CONST_CLA = ClaBits.GP | ClaBits.First.GP_SECURE
# Allowed values for security_level parameter
ALLOWED_SECURITY_LEVELS = (
    SecurityLevel.CLEAR,
    SecurityLevel.C_MAC,
    SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC,
    SecurityLevel.C_MAC | SecurityLevel.R_MAC,
    SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC | SecurityLevel.R_MAC,
    (SecurityLevel.C_DECRYPTION | SecurityLevel.R_ENCRYPTION |
     SecurityLevel.C_MAC | SecurityLevel.R_MAC))


class IParam:
    """Bits of the "i" parameter"""
    # If set the card uses pseudo-random card challenge
    PRNG = 0b00010000
    # R-MAC support
    R_MAC = 0b00100000
    # R-MAC and R-ENCRYPTION support
    R_MAC_ENC = 0b01100000


class DDC:
    """Data derivation constants"""
    # Card authentication cryptogram
    CARD_CRYPTOGRAM = 0b00000000
    # Host authentication cryptogram
    HOST_CRYPTOGRAM = 0b00000001
    # Card challenge
    CARD_CHALLENGE = 0b00000010
    # Derivation of S-ENC session key
    S_ENC = 0b00000100
    # Derivation of S-MAC session key
    S_MAC = 0b00000110
    # Derivation of S-RMAC session key
    S_RMAC = 0b00000111


def _derive_data(key, ddc_const: int, L: int, context):
    """Derive data following SCP 03 data derivation scheme."""
    assert L >= 8 and (L & 0b111) == 0
    kdf = crypto.KBKDF(crypto.CMAC(crypto.AES, key), ctrlen_bytes=1,
                       ctr_loc=crypto.KBKDF.LOC_MIDDLE_FIXED,
                       mode=crypto.KBKDF.MODE_COUNTER)
    return kdf.derive(L >> 3, 11 * b'\0' + pack(">BBH", ddc_const, 0, L),
                      context)


def _compute_block_size(block_size_in: int,
                        security_level: SecurityLevel) -> int:
    """Compute maximum block size for the specified security level."""
    if block_size_in <= 0 or block_size_in > LC_MAX:
        raise ValueError("Invalid block size")

    block_size = block_size_in
    if security_level & SecurityLevel.C_MAC:
        block_size -= MAC_N_BYTES
    if security_level & SecurityLevel.C_DECRYPTION:
        block_size -= block_size % crypto.AES.BLOCK_N_BYTES
        block_size -= 1  # At least one padding byte

    if block_size <= 0:
        raise ValueError("Invalid block size")

    return block_size


class SCP03:
    """Secure Channel Protocol version 03"""
    # SCP version
    _VERSION = 3

    def __init__(self, card_obj, iu_response, keys: StaticKeys,
                 security_level: SecurityLevel, host_challenge,
                 block_size, buggy_icv_counter, **options):
        if security_level not in ALLOWED_SECURITY_LEVELS:
            raise ValueError("Invalid security level")
        self._debug = card_obj.debug
        self._security_level = security_level
        self._intf_block_size = block_size
        self._block_size = _compute_block_size(block_size, security_level)
        self._buggy_icv_counter = buggy_icv_counter

        # Parse INITIALIZE UPDATE response
        if len(iu_response) < 29:
            raise RuntimeError("Invalid INITIALIZE UPDATE response")
        stream = BytesIO(iu_response)
        key_dvs_data = stream.read(10)
        key_ver = stream.read(1)[0]
        scp_id = stream.read(1)[0]
        self._scp_i = stream.read(1)[0]
        card_challenge = stream.read(8)
        card_cryptogram = stream.read(8)
        seq_ctr = stream.read(3)
        if scp_id != self._VERSION:
            raise RuntimeError("Invalid INITIALIZE UPDATE response")
        if self._scp_i & IParam.PRNG and len(seq_ctr) != 3:
            raise RuntimeError("Invalid INITIALIZE UPDATE response")
        if self._debug:
            print("SCP %02x, key version %02x, i=%02x" % (scp_id, key_ver,
                                                          self._scp_i))
            print("Host challenge:", hexlify(host_challenge).decode())
            print("Card challenge:", hexlify(card_challenge).decode())
            print("Card cryptogram:", hexlify(card_cryptogram).decode())
            print("Key diversification data:", hexlify(key_dvs_data).decode())
            if seq_ctr:
                print("Sequence counter:", hexlify(seq_ctr).decode())

        # Diversify static keys and derive session keys
        dvs_keys = self._diversify_keys(keys, key_dvs_data)
        self._initialize_keys(dvs_keys, host_challenge, card_challenge)
        if self._debug:
            print("Key-DEK:", hexlify(self._key_dek).decode())
            print("S-ENC:", hexlify(self._s_enc).decode())
            print("S-MAC:", hexlify(self._s_mac).decode())
            print("S-RMAC:", hexlify(self._s_rmac).decode())

        # Generate and verify authentication cryptograms
        cryptogram_ctx = host_challenge + card_challenge
        card_cryptogram_check = _derive_data(self._s_mac, DDC.CARD_CRYPTOGRAM,
                                             CRYPTOGRAM_N_BITS, cryptogram_ctx)
        host_cryptogram = _derive_data(self._s_mac, DDC.HOST_CRYPTOGRAM,
                                       CHALLENGE_N_BITS, cryptogram_ctx)
        if card_cryptogram_check != card_cryptogram:
            raise RuntimeError("Invalid card authentication cryptogram")

        # Authenticate host with EXTERNAL AUTHENTICATE selecting security level
        p1p2 = bytes([security_level, 0])
        _, sw = card_obj.request_full(
            self.wrap_apdu(EXTERNAL_AUTHENTICATE + p1p2 +
                           card.encode(host_cryptogram),
                           sl_override=SecurityLevel.C_MAC))
        if sw != status.SUCCESS:
            raise RuntimeError("EXTERNAL AUTHENTICATE failed")

    @property
    def block_size(self):
        return self._block_size

    def _diversify_keys(self, keys: StaticKeys, key_dvs_data):
        """Diversify keys."""
        # Currently does nothing
        return keys

    def _initialize_keys(self, keys: StaticKeys, host_challenge, card_challenge):
        """Derive session keys and initialize security parameters."""
        if len(keys.key_enc) != len(keys.key_mac) != len(keys.key_dek):
            raise ValueError("Keys must have the same length")
        if len(keys.key_enc) not in crypto.AES.ALLOWED_KEY_LEN:
            raise ValueError("Invalid length of an AES key")
        n_bits = 8 * len(keys.key_enc)

        # Save Key-DEK as is
        self._key_dek = keys.key_dek

        # Derive session keys
        context = host_challenge + card_challenge
        self._s_enc = _derive_data(keys.key_enc, DDC.S_ENC, n_bits, context)
        self._s_mac = _derive_data(keys.key_mac, DDC.S_MAC, n_bits, context)
        self._s_rmac = _derive_data(keys.key_mac, DDC.S_RMAC, n_bits, context)

        # Create instances of cryptographic primitives with session keys
        self._s_mac_inst = crypto.CMAC(crypto.AES, self._s_mac)
        self._s_rmac_inst = crypto.CMAC(crypto.AES, self._s_rmac, MAC_N_BYTES)

        # Initialize MAC chaining value with zeroes
        self._mac_chain = 16 * b'\0'
        # Initialize encryption counter
        self._enc_ctr = 0

    def wrap_apdu(self, apdu: bytes, sl_override=None) -> bytes:
        """Apply secure channel wrapping to APDU."""
        sl = sl_override if sl_override is not None else self._security_level
        if not isinstance(apdu, bytearray):
            apdu = bytearray(apdu)
        if len(apdu) < OFF_DATA or apdu[OFF_LC] != len(apdu) - OFF_DATA:
            raise ValueError("Invalid APDU")
        if apdu[OFF_LC] > self.block_size:
            raise ValueError("APDU too long for wrapping")

        # TODO: encryption and R-MAC over non-segmented data for GET RESPONSE
        if apdu[OFF_INS] == GET_RESPONSE[OFF_INS]:
            return apdu

        # Encrypt data field if needeed
        if sl & SecurityLevel.C_DECRYPTION:
            if apdu[OFF_LC] > 0 or self._buggy_icv_counter:
                self._enc_ctr += 1
                if self._enc_ctr >= 0x80000000000000000000000000000000:
                    raise RuntimeError("Encryption counter overflow")
            if apdu[OFF_LC] > 0:
                ctr = int_to_bytes_big_endian(self._enc_ctr, CTR_N_BYTES)
                icv = crypto.AES(self._s_enc, crypto.MODE_ECB).encrypt(ctr)
                aes_cbc = crypto.AES(self._s_enc, crypto.MODE_CBC, icv)
                ct = aes_cbc.encrypt(aes_cbc.add_padding(apdu[OFF_DATA:]))
                apdu = apdu[:OFF_DATA] + ct
                apdu[OFF_LC] = len(ct)

        # Add MAC if needed, also patching the CLA byte
        if sl & SecurityLevel.C_MAC:
            orig_cla, apdu[OFF_CLA] = apdu[OFF_CLA], MAC_CONST_CLA
            apdu[OFF_LC] += MAC_N_BYTES
            self._mac_chain = self._s_mac_inst.mac(self._mac_chain + apdu)
            apdu += self._mac_chain[:MAC_N_BYTES]
            if orig_cla & ClaBits.FURTHER:
                apdu[OFF_CLA] = orig_cla | ClaBits.Further.SECURE
            else:
                apdu[OFF_CLA] = orig_cla | ClaBits.First.GP_SECURE

        assert apdu[OFF_LC] <= self._intf_block_size
        return bytes(apdu)

    def unwrap_response(self, data: bytes, sw: bytes) -> bytes:
        """Remove secure channel wrapping from APDU response."""
        if not isinstance(data, bytearray):
            data = bytearray(data)

        # Verify MAC if needed
        if self._security_level & SecurityLevel.R_MAC:
            if len(data) < MAC_N_BYTES:  # Check for MAC in response
                if status.is_error(sw) and len(data) == 0:
                    return b'', sw
                raise RuntimeError("Invalid APDU response")
            mac = data[-MAC_N_BYTES:]
            data = data[:-MAC_N_BYTES]
            if mac != self._s_rmac_inst.mac(self._mac_chain + data + sw):
                raise RuntimeError("Invalid APDU response")

        # Decrypt data if needed
        if self._security_level & SecurityLevel.R_ENCRYPTION and len(data):
            if len(data) % crypto.AES.BLOCK_N_BYTES != 0:
                raise RuntimeError("Invalid APDU response")
            ctr = int_to_bytes_big_endian(self._enc_ctr, CTR_N_BYTES)
            ctr[0] |= 0x80
            icv = crypto.AES(self._s_enc, crypto.MODE_ECB).encrypt(ctr)
            aes_cbc = crypto.AES(self._s_enc, crypto.MODE_CBC, icv)
            data = aes_cbc.remove_padding(aes_cbc.decrypt(data))

        return bytes(data), sw

    def encrypt_data(self, data):
        """Encrypt sensitive data with Key-DEK."""
        if len(data) == 0 or (len(data) % crypto.AES.BLOCK_N_BYTES) != 0:
            raise ValueError("Data block must be a multiple of cipher block")
        icv = crypto.AES.BLOCK_N_BYTES * b'\0'
        return crypto.AES(self._key_dek, crypto.MODE_CBC, icv).encrypt(data)

    def decrypt_data(self, data):
        """Decrypt sensitive data with Key-DEK."""
        if len(data) == 0 or (len(data) % crypto.AES.BLOCK_N_BYTES) != 0:
            raise ValueError("Data block must be a multiple of cipher block")
        icv = crypto.AES.BLOCK_N_BYTES * b'\0'
        return crypto.AES(self._key_dek, crypto.MODE_CBC, icv).decrypt(data)

    def close(self):
        """Clear all session data."""
        del self._security_level
        del self._key_dek
        del self._s_enc
        del self._s_mac
        del self._s_rmac
        del self._s_mac_inst
        del self._s_rmac_inst
        del self._mac_chain
        del self._enc_ctr

    @property
    def version(self):
        return self._VERSION
