from binascii import unhexlify as unhex
import pytest
import omfgp.scp
from omfgp.scp03 import *
from omfgp.scp03 import _derive_data, _compute_block_size


def test_derive_data():
    key = unhex("404142434445464748494A4B4C4D4E4F")
    context = unhex("68E9C8799FF8CB46F8D89D88BA1287BF")
    s_enc = _derive_data(key, DDC.S_ENC, len(key) * 8, context)
    assert s_enc == unhex("3C64070C595D1D72BDEE692DA99B7AE4")
    s_mac = _derive_data(key, DDC.S_MAC, len(key) * 8, context)
    assert s_mac == unhex("6E8468B74A707842E3D3696F338D2657")
    s_rmac = _derive_data(key, DDC.S_RMAC, len(key) * 8, context)
    assert s_rmac == unhex("FDD1D7C84750994815D0082734C31D88")
    card_cryptogram = _derive_data(s_mac, DDC.CARD_CRYPTOGRAM, 0x0040, context)
    assert card_cryptogram == unhex("9B5C9D42D5059430")
    host_cryptogram = _derive_data(s_mac, DDC.HOST_CRYPTOGRAM, 0x0040, context)
    assert host_cryptogram == unhex("F3C7624565B5894F")


def test_derive_card_challenge():
    key_enc = unhex("404142434445464748494A4B4C4D4E4F")
    sd_aid = unhex("A000000018434D08090A0B0C000000")
    seq_ctr = unhex("00002A")
    context = seq_ctr + sd_aid
    card_challenge = _derive_data(key_enc, DDC.CARD_CHALLENGE, 0x0040, context)
    assert card_challenge == unhex("A3F5F144D19BE66E")


def test_compute_block_size():
    assert _compute_block_size(100, SecurityLevel.CLEAR) == 100
    assert _compute_block_size(100, SecurityLevel.C_MAC) == 92
    assert _compute_block_size(
        100, SecurityLevel.C_MAC | SecurityLevel.C_DECRYPTION) == 79
    assert _compute_block_size(
        24, SecurityLevel.C_MAC | SecurityLevel.C_DECRYPTION) == 15
    with pytest.raises(Exception):
        _compute_block_size(8, SecurityLevel.C_MAC)
    with pytest.raises(Exception):
        _compute_block_size(
            23, SecurityLevel.C_MAC | SecurityLevel.C_DECRYPTION)
