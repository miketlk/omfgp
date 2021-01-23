import pytest
import omfgp.scp
from omfgp.scp02 import *
from omfgp.scp02 import _derive_key


def test_derive_key():
    base_key = bytes.fromhex("404142434445464748494A4B4C4D4E4F")
    assert (_derive_key(base_key, KDC.SESSION_CMAC, bytes.fromhex("0007")) ==
            bytes.fromhex("7A227D376A9DBE23AB50B7DCB45B2093"))
    assert (_derive_key(base_key, KDC.SESSION_RMAC, bytes.fromhex("0007")) ==
            bytes.fromhex("EF14C57DB4BB9015E88963D9D920A588"))
    assert (_derive_key(base_key, KDC.SESSION_ENC, bytes.fromhex("0007")) ==
            bytes.fromhex("A2268F71917EFE0F33CC6166E1154E27"))
