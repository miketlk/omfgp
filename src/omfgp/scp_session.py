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


def open_secure_channel(card_obj, keys: StaticKeys = DEFAULT_KEYS,
                        progress_cb=None, **scp_options):
    """Opens secure channel returning secure channel object"""

    # Combine options with the default values, validate and correct if needed
    options = {'key_version': 0,
               'security_level': SecurityLevel.C_MAC,
               'host_challenge': crypto.random(HOST_CHALLENGE_SIZE),
               'block_size': commands.LC_MAX,
               'buggy_icv_counter': False,
               'min_scp_version': 0}
    options.update(scp_options)
    key_version = options['key_version']
    options['security_level'] = SecurityLevel(options['security_level'])
    host_challenge = options['host_challenge']
    if key_version != 0 and not (0x30 <= key_version <= 0x3F):
        raise ValueError("Invalid key version: %x" % key_version)
    if len(host_challenge) != HOST_CHALLENGE_SIZE:
        raise ValueError("Host challenge must be %d bytes" %
                         HOST_CHALLENGE_SIZE)

    # Create progress wrapper and report progress: 0%
    progress_cb = ProgressCallback(progress_cb)
    progress_cb(0)

    # Send INITIALIZE UPDATE to start a new session
    p1p2 = bytes([key_version, 0x00])
    iu_response, sw = card_obj.request_full(
        commands.INITIALIZE_UPDATE + p1p2 + card.encode(host_challenge))
    if sw != status.SUCCESS:
        raise RuntimeError("INITIALIZE UPDATE failed")
    if len(iu_response) < IU_RESP_SCP_ID + 1:
        raise RuntimeError("Invalid INITIALIZE UPDATE response")
    if key_version != 0 and iu_response[IU_RESP_KEY_VER] != key_version:
        raise RuntimeError("Invalid INITIALIZE UPDATE response")

    progress_cb(50)

    # Create protocol wrapper according to received SCP version
    if iu_response[IU_RESP_SCP_ID] < options['min_scp_version']:
        raise RuntimeError("")
    if iu_response[IU_RESP_SCP_ID] == 3:
        obj = scp03.SCP03(card_obj, iu_response, keys, **options)
    else:
        raise RuntimeError(
            "Secure protocol version %d not supported" %
            iu_response[IU_RESP_SCP_ID])

    # Done, report 100% completeness
    progress_cb(100)
    return obj
