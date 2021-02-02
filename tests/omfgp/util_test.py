import pytest
from omfgp.util import *


def test_aid_to_str():
    assert aid_to_str(b'\x00') == "0"
    assert aid_to_str(b'\x0a') == "A"
    assert aid_to_str(b'\xa0') == "A0"
    assert aid_to_str(b'\x0a\x00') == "A00"
    assert aid_to_str(b'\xa0\x00') == "A000"
    assert aid_to_str(b'\x12\x34\x5a\xbc\xde\xf0') == "12345ABCDEF0"


def test_int_to_bytes_big_endian():
    assert int_to_bytes_big_endian(0, 0) == b''
    assert int_to_bytes_big_endian(0, 1) == bytes.fromhex("00")
    assert int_to_bytes_big_endian(0, 2) == bytes.fromhex("0000")
    assert int_to_bytes_big_endian(0, 3) == bytes.fromhex("000000")
    assert int_to_bytes_big_endian(0, 4) == bytes.fromhex("00000000")
    assert int_to_bytes_big_endian(0xffffffff, 4) == bytes.fromhex("ffffffff")
    assert int_to_bytes_big_endian(
        0x123456789ABCDEF0, 8) == bytes.fromhex("123456789ABCDEF0")
    assert int_to_bytes_big_endian(
        0x123456789ABCDEF0, 10) == bytes.fromhex("0000123456789ABCDEF0")
    with pytest.raises(ValueError):
        assert int_to_bytes_big_endian(1, 0)
    with pytest.raises(ValueError):
        assert int_to_bytes_big_endian(0x123, 1)
    with pytest.raises(ValueError):
        assert int_to_bytes_big_endian(0x12345, 2)
    with pytest.raises(ValueError):
        assert int_to_bytes_big_endian(0xfffff, 2)

def test_xor_bytes():
    a = bytes.fromhex("123456")
    b = bytes.fromhex("abcdef")
    assert xor_bytes(a, b) == bytes.fromhex("b9f9b9")
    assert xor_bytes(b'', b'') == b''
    with pytest.raises(ValueError):
        xor_bytes(a, bytes.fromhex("abcd"))


def test_lshift1():
    data = bytes.fromhex("abcdef123456")
    assert lshift1_bytes(data) == bytes.fromhex("579bde2468ac")