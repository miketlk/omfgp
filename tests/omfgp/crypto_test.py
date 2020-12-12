import pytest
import omfgp.crypto as crypto
from omfgp.crypto import xor_bytes, _lshift1


def test_aes_ecb():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                        "101112131415161718191a1b1c1d1e1f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    assert crypto.AES(key, crypto.MODE_ECB).encrypt(pt) == ct
    assert crypto.AES(key, crypto.MODE_ECB).decrypt(ct) == pt


def test_aes_cbc():
    key = bytes.fromhex("0493ff637108af6a5b8e90ac1fdf035a"
                        "3d4bafd1afb573be7ade9e8682e663e5")
    iv = bytes.fromhex("c0cd2bebccbb6c49920bd5482ac756e8")
    pt = bytes.fromhex("8b37f9148df4bb25956be6310c73c8dc"
                       "58ea9714ff49b643107b34c9bff096a9"
                       "4fedd6823526abc27a8e0b16616eee25"
                       "4ab4567dd68e8ccd4c38ac563b13639c")
    ct = bytes.fromhex("05d5c77729421b08b737e41119fa4438"
                       "d1f570cc772a4d6c3df7ffeda0384ef8"
                       "4288ce37fc4c4c7d1125a499b051364c"
                       "389fd639bdda647daa3bdadab2eb5594")
    assert crypto.AES(key, crypto.MODE_CBC, iv).encrypt(pt) == ct
    assert crypto.AES(key, crypto.MODE_CBC, iv).decrypt(ct) == pt


def test_xor_bytes():
    a = bytes.fromhex("123456")
    b = bytes.fromhex("abcdef")
    assert xor_bytes(a, b) == bytes.fromhex("b9f9b9")
    assert xor_bytes(b'', b'') == b''
    with pytest.raises(ValueError):
        xor_bytes(a, bytes.fromhex("abcd"))


def test_lshift1():
    data = bytes.fromhex("abcdef123456")
    assert _lshift1(data) == bytes.fromhex("579bde2468ac")


def test_aes_cmac():
    # 128-bit key
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    mac = crypto.CMAC(crypto.AES, key).mac(b'')
    assert mac == bytes.fromhex("bb1d6929e95937287fa37d129b756746")
    mac = crypto.CMAC(crypto.AES, key).mac(
        bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"))
    assert mac == bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")
    mac = crypto.CMAC(crypto.AES, key).mac(
        bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a57"))
    assert mac == bytes.fromhex("7d85449ea6ea19c823a7bf78837dfade")
    mac = crypto.CMAC(crypto.AES, key).mac(
        bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"
                      "ae2d8a571e03ac9c9eb76fac45af8e51"
                      "30c81c46a35ce411e5fbc1191a0a52ef"
                      "f69f2445df4f9b17ad2b417be66c3710"))
    assert mac == bytes.fromhex("51f0bebf7e3b9d92fc49741779363cfe")

    # 256-bit key
    key = bytes.fromhex("95d8afb8a4b7245ce79f9f9c5ddd40de"
                        "61b35905dcb638f2b875404a985b3f7a")
    mac = crypto.CMAC(crypto.AES, key, tlen_bytes=5).mac(b'')
    assert mac == bytes.fromhex("68adfc9b59")
    key = bytes.fromhex("2f4a6501d8fe7b65f607757ddff6ed87"
                        "ae0681b98b53331d2d46109f9c541065")
    mac = crypto.CMAC(crypto.AES, key, tlen_bytes=10).mac(
        bytes.fromhex("4fa9ac1b544afcd85ac32ac0909c74"))
    assert mac == bytes.fromhex("c02e8b66f9fc263b8fb0")


def test_aes_cmac_variable_tlen():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    mac = crypto.CMAC(crypto.AES, key, tlen_bytes=1).mac(b'')
    assert mac == bytes.fromhex("bb")
    mac = crypto.CMAC(crypto.AES, key, tlen_bytes=7).mac(b'')
    assert mac == bytes.fromhex("bb1d6929e95937")
    mac = crypto.CMAC(crypto.AES, key, tlen_bytes=15).mac(b'')
    assert mac == bytes.fromhex("bb1d6929e95937287fa37d129b7567")
    mac = crypto.CMAC(crypto.AES, key, tlen_bytes=16).mac(b'')
    assert mac == bytes.fromhex("bb1d6929e95937287fa37d129b756746")
    with pytest.raises(ValueError):
        crypto.CMAC(crypto.AES, key, tlen_bytes=0).mac(b'')
    with pytest.raises(ValueError):
        crypto.CMAC(crypto.AES, key, tlen_bytes=17).mac(b'')
