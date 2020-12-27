"""Common parts of Secure Channel Protocols"""

from collections import namedtuple
from binascii import hexlify
from . import card
from . import commands
from . import status
from . import crypto
from .scp import *
from .util import ProgressCallback
from . import scp02, scp03


def open_secure_channel(card_obj, keys: StaticKeys,
                        key_version: int = 0,
                        security_level: int = SecurityLevel.C_MAC,
                        host_challenge=None, sd_aid=None,
                        block_size: int = commands.LC_MAX,
                        progress_cb=None, buggy_icv_counter=False):
    """Opens secure channel returning secure channel object"""
    if key_version != 0 and not (0x30 <= key_version <= 0x3F):
        raise ValueError("Invalid key version: %x" % key_version)

    progress_cb = ProgressCallback(progress_cb)
    progress_cb(0)

    if host_challenge is None:
        host_challenge = crypto.random(HOST_CHALLENGE_SIZE)
    elif len(host_challenge) != HOST_CHALLENGE_SIZE:
        raise ValueError("Host challenge must be %d bytes" %
                         HOST_CHALLENGE_SIZE)
    if card_obj.debug:
        print("Host challenge:", hexlify(host_challenge).decode())

    p1p2 = b'\x00\x00'  # First available key
    iu_response, sw = card_obj.request_full(
        commands.INITIALIZE_UPDATE + p1p2 + card.encode(host_challenge))
    if sw != status.SUCCESS:
        raise RuntimeError("INITIALIZE UPDATE failed")
    if len(iu_response) < IU_RESP_SCP_ID + 1:
        raise RuntimeError("Invalid INITIALIZE UPDATE response")
    if key_version != 0 and iu_response[IU_RESP_KEY_VER] != key_version:
        raise RuntimeError("Invalid INITIALIZE UPDATE response")

    progress_cb(50)

    if iu_response[IU_RESP_SCP_ID] == 3:
        obj = scp03.SCP03(card_obj, iu_response, keys,
                          SecurityLevel(security_level), host_challenge,
                          sd_aid, block_size, buggy_icv_counter)
    else:
        raise RuntimeError(
            "Secure protocol version %d not supported" %
            iu_response[IU_RESP_SCP_ID])

    progress_cb(100)
    return obj
