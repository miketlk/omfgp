import pytest
import omfgp.crypto as crypto


def test_random():
    a = crypto.random(16)
    b = crypto.random(16)
    c = crypto.random(16)
    assert len(a) == 16 and len(b) == 16 and len(c) == 16
    assert a != b and a != c and b != c


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


def test_cmac_aes():
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


def test_cmac_aes_variable_tlen():
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


def test_kbkdf_counter_mode_cmac_aes():
    # Derive 16 bytes using CMAC-AES128, 1-byte counter before fixed part
    key = bytes.fromhex("dff1e50ac0b69dc40f1051d46c2b069c")
    kdf = crypto.KBKDF(crypto.CMAC(crypto.AES, key), ctrlen_bytes=1,
                       ctr_loc=crypto.KBKDF.LOC_BEFORE_FIXED,
                       mode=crypto.KBKDF.MODE_COUNTER)
    out = kdf.derive(16, bytes.fromhex("c16e6e02c5a3dcc8d78b9ac130687776"
                                       "1310455b4e41469951d9e6c2245a064b"
                                       "33fd8c3b01203a7824485bf0a64060c4"
                                       "648b707d2607935699316ea5"))
    assert out == bytes.fromhex("8be8f0869b3c0ba97b71863d1b9f7813")
    # Same test, data is broken in two pieces
    out = kdf.derive(16, bytes.fromhex("c16e6e02c5a3dcc8d78b9ac130687776"
                                       "1310455b4e41469951d9e6c2245a064b"
                                       "33fd8c3b01203a7824485bf0a64060c4"),
                     bytes.fromhex("648b707d2607935699316ea5"))
    assert out == bytes.fromhex("8be8f0869b3c0ba97b71863d1b9f7813")

    # Derive 20 bytes using CMAC-AES128, 1-byte counter before fixed part
    key = bytes.fromhex("7aa9973481d560f3be217ac3341144d8")
    kdf = crypto.KBKDF(crypto.CMAC(crypto.AES, key), ctrlen_bytes=1,
                       ctr_loc=crypto.KBKDF.LOC_BEFORE_FIXED,
                       mode=crypto.KBKDF.MODE_COUNTER)
    out = kdf.derive(20, bytes.fromhex("46f88b5af7fb9e29262dd4e010143a0a"
                                       "9c465c627450ec74ab7251889529193e"
                                       "995c4b56ff55bc2fc8992a0df1ee8056"
                                       "f6816b7614fba4c12d3be1a5"))
    assert out == bytes.fromhex("1746ae4f09903f74bfbe1b8ae2b79d74576a3b09")

    # Derive 40 bytes using CMAC-AES128, 1-byte counter before fixed part
    key = bytes.fromhex("bb31eef5a2ca3bfb342c5800fee67313")
    kdf = crypto.KBKDF(crypto.CMAC(crypto.AES, key), ctrlen_bytes=1,
                       ctr_loc=crypto.KBKDF.LOC_BEFORE_FIXED,
                       mode=crypto.KBKDF.MODE_COUNTER)
    out = kdf.derive(40, bytes.fromhex("f85ae18f15ce1a5e036d6e3fd227243a"
                                       "9863f88ef532ce1da810b6639c0928f9"
                                       "b99fe909487d3748cff857cdb790f89e"
                                       "09d8c634dccb616cf7a2663a"))
    assert out == bytes.fromhex("8923d38effde99e24f67dec9330c4f1b"
                                "874fc382ad644140e73a8e406f405d3f"
                                "e4b4730b7291275a")

    # Derive 16 bytes using CMAC-AES128, 2-byte counter before fixed part
    key = bytes.fromhex("30ec5f6fa1def33cff008178c4454211")
    kdf = crypto.KBKDF(crypto.CMAC(crypto.AES, key), ctrlen_bytes=2,
                       ctr_loc=crypto.KBKDF.LOC_BEFORE_FIXED,
                       mode=crypto.KBKDF.MODE_COUNTER)
    out = kdf.derive(16, bytes.fromhex("c95e7b1d4f2570259abfc05bb00730f0"
                                       "284c3bb9a61d07259848a1cb57c81d8a"
                                       "6c3382c500bf801dfc8f70726b082cf4"
                                       "c3fa34386c1e7bf0e5471438"))
    assert out == bytes.fromhex("00018fff9574994f5c4457f461c7a67e")

    # Derive 16 bytes using CMAC-AES128, 3-byte counter before fixed part
    key = bytes.fromhex("ca1cf43e5ccd512cc719a2f9de41734c")
    kdf = crypto.KBKDF(crypto.CMAC(crypto.AES, key), ctrlen_bytes=3,
                       ctr_loc=crypto.KBKDF.LOC_BEFORE_FIXED,
                       mode=crypto.KBKDF.MODE_COUNTER)
    out = kdf.derive(16, bytes.fromhex("e3884ac963196f02ddd09fc04c20c88b"
                                       "60faa775b5ef6feb1faf8c5e098b5210"
                                       "e2b4e45d62cc0bf907fd68022ee7b156"
                                       "31b5c8daf903d99642c5b831"))
    assert out == bytes.fromhex("1cb2b12326cc5ec1eba248167f0efd58")

    # Derive 16 bytes using CMAC-AES128, 4-byte counter before fixed part
    key = bytes.fromhex("c10b152e8c97b77e18704e0f0bd38305")
    kdf = crypto.KBKDF(crypto.CMAC(crypto.AES, key), ctrlen_bytes=4,
                       ctr_loc=crypto.KBKDF.LOC_BEFORE_FIXED,
                       mode=crypto.KBKDF.MODE_COUNTER)
    out = kdf.derive(16, bytes.fromhex("98cd4cbbbebe15d17dc86e6dbad800a2"
                                       "dcbd64f7c7ad0e78e9cf94ffdba89d03"
                                       "e97eadf6c4f7b806caf52aa38f09d0eb"
                                       "71d71f497bcc6906b48d36c4"))
    assert out == bytes.fromhex("26faf61908ad9ee881b8305c221db53f")

    # Derive 16 bytes using CMAC-AES128, 1-byte counter after fixed part
    key = bytes.fromhex("e61a51e1633e7d0de704dcebbd8f962f")
    kdf = crypto.KBKDF(crypto.CMAC(crypto.AES, key), ctrlen_bytes=1,
                       ctr_loc=crypto.KBKDF.LOC_AFTER_FIXED,
                       mode=crypto.KBKDF.MODE_COUNTER)
    out = kdf.derive(16, bytes.fromhex("5eef88f8cb188e63e08e23c957ee424a"
                                       "3345da88400c567548b57693931a8475"
                                       "01f8e1bce1c37a09ef8c6e2ad553dd0f"
                                       "603b52cc6d4e4cbb76eb6c8f"))
    assert out == bytes.fromhex("63a5647d0fe69d21fc420b1a8ce34cc1")
    # Same test, data is broken in two pieces
    out = kdf.derive(16, bytes.fromhex("5eef88f8cb188e63e08e23c957ee424a"
                                       "3345da88400c567548b57693931a8475"
                                       "01f8e1bce1c37a09ef8c6e2ad553dd0f"),
                     bytes.fromhex("603b52cc6d4e4cbb76eb6c8f"))
    assert out == bytes.fromhex("63a5647d0fe69d21fc420b1a8ce34cc1")

    # Derive 16 bytes using CMAC-AES128, 1-byte counter in the middle
    key = bytes.fromhex("b6e04abd1651f8794d4326f4c684e631")
    kdf = crypto.KBKDF(crypto.CMAC(crypto.AES, key), ctrlen_bytes=1,
                       ctr_loc=crypto.KBKDF.LOC_MIDDLE_FIXED,
                       mode=crypto.KBKDF.MODE_COUNTER)
    out = kdf.derive(16, bytes.fromhex("93612f7256c46a3d856d3e951e32dbf1"
                                       "5fe11159d0b389ad38d603850fee6d18"
                                       "d22031435ed36ee20da76745fbea4b10fe1e"),
                     bytes.fromhex("99322aae605a5f01e32b"))
    assert out == bytes.fromhex("dcb1db87a68762c6b3354779fa590bef")

    # Derive 16 bytes using CMAC-AES256, 1-byte counter before fixed part
    key = bytes.fromhex("aeb7201d055f754212b3e497bd0b2578"
                        "9a49e51da9f363df414a0f80e6f4e42c")
    kdf = crypto.KBKDF(crypto.CMAC(crypto.AES, key), ctrlen_bytes=1,
                       ctr_loc=crypto.KBKDF.LOC_BEFORE_FIXED,
                       mode=crypto.KBKDF.MODE_COUNTER)
    out = kdf.derive(16, bytes.fromhex("11ec30761780d4c44acb1f26ca1eb770"
                                       "f87c0e74505e15b7e456b019ce0c3810"
                                       "3c4d14afa1de71d340db514105966275"
                                       "12cf199fffa20ef8c5f4841e"))
    assert out == bytes.fromhex("2a9e2fe078bd4f5d3076d14d46f39fb2")


def test_add_padding():
    assert crypto.add_padding(b'', 16) == bytes.fromhex(
        "80000000000000000000000000000000")
    assert crypto.add_padding(b'\x01', 16) == bytes.fromhex(
        "01800000000000000000000000000000")
    assert crypto.add_padding(b'\x80', 16) == bytes.fromhex(
        "80800000000000000000000000000000")
    assert crypto.add_padding(bytes.fromhex("010203"), 16) == bytes.fromhex(
        "01020380000000000000000000000000")
    assert crypto.add_padding(
        bytes.fromhex("010203040506070809101112131415"), 16) == bytes.fromhex(
        "01020304050607080910111213141580")
    assert crypto.add_padding(
        bytes.fromhex("01020304050607080910111213141516"), 16) == bytes.fromhex(
        "0102030405060708091011121314151680000000000000000000000000000000")


def test_add_padding_aes():
    aes = crypto.AES(16 * b'\0', crypto.MODE_CBC, 16 * b'\0')
    assert aes.add_padding(b'') == bytes.fromhex(
        "80000000000000000000000000000000")
    assert aes.add_padding(bytes.fromhex("010203")) == bytes.fromhex(
        "01020380000000000000000000000000")
    assert aes.add_padding(
        bytes.fromhex("01020304050607080910111213141516")) == bytes.fromhex(
        "0102030405060708091011121314151680000000000000000000000000000000")


def test_remove_padding():
    assert crypto.remove_padding(
        bytes.fromhex("80000000000000000000000000000000"), 16) == b''
    assert crypto.remove_padding(
        bytes.fromhex("01800000000000000000000000000000"), 16) == b'\x01'
    assert crypto.remove_padding(
        bytes.fromhex("80800000000000000000000000000000"), 16) == b'\x80'
    assert crypto.remove_padding(
        bytes.fromhex("01020380000000000000000000000000"), 16) == bytes.fromhex(
            "010203")
    assert crypto.remove_padding(
        bytes.fromhex("01020304050607080910111213141580"), 16) == bytes.fromhex(
        "010203040506070809101112131415")
    assert crypto.remove_padding(
        bytes.fromhex("01020304050607080910111213141516"
                      "80000000000000000000000000000000"), 16) == bytes.fromhex(
        "01020304050607080910111213141516")


def test_remove_padding_fail():
    with pytest.raises(ValueError):
        # Empty data
        crypto.remove_padding(b'', 16)
    with pytest.raises(ValueError):
        # No 0x80 byte
        crypto.remove_padding(
            bytes.fromhex("00000000000000000000000000000000"), 16)
    with pytest.raises(ValueError):
        # Length is not a multiple of block size
        crypto.remove_padding(
            bytes.fromhex("800000000000000000000000000000"), 16)
    with pytest.raises(ValueError):
        # Invalid byte inside padding part (0x01)
        crypto.remove_padding(
            bytes.fromhex("8001000000000000000000000000000"), 16)


def test_remove_padding_aes():
    aes = crypto.AES(16 * b'\0', crypto.MODE_CBC, 16 * b'\0')
    assert aes.remove_padding(
        bytes.fromhex("80000000000000000000000000000000")) == b''
    assert aes.remove_padding(
        bytes.fromhex("01020380000000000000000000000000")) == bytes.fromhex(
            "010203")
    assert aes.remove_padding(
        bytes.fromhex("01020304050607080910111213141516"
                      "80000000000000000000000000000000")) == bytes.fromhex(
        "01020304050607080910111213141516")


def test_des_ecb():
    key = bytes.fromhex("0123456789abcdef")
    pt = bytes.fromhex("6bc1bee22e409f96")
    ct = bytes.fromhex("7277a00dc1c1c36b")
    assert crypto.DES(key, crypto.MODE_ECB).encrypt(pt) == ct
    assert crypto.DES(key, crypto.MODE_ECB).decrypt(ct) == pt


def test_tdes128_ecb():
    key = bytes.fromhex("0123456789abcdef23456789abcdef01")
    pt = bytes.fromhex("6bc1bee22e409f96")
    ct = bytes.fromhex("06ede3d82884090a")
    assert crypto.DES(key, crypto.MODE_ECB).encrypt(pt) == ct
    assert crypto.DES(key, crypto.MODE_ECB).decrypt(ct) == pt


def test_tdes192_ecb():
    key = bytes.fromhex("0123456789abcdef23456789abcdef010123456789abcdef")
    pt = bytes.fromhex("6bc1bee22e409f96")
    ct = bytes.fromhex("06ede3d82884090a")
    assert crypto.DES(key, crypto.MODE_ECB).encrypt(pt) == ct
    assert crypto.DES(key, crypto.MODE_ECB).decrypt(ct) == pt


def test_tdes_cbc():
    key = bytes.fromhex("08763da862ad16ef5815408f5d3b705415ab1543a42c3efb")
    iv = bytes.fromhex("0634d69eaff3ae17")
    pt = bytes.fromhex("109a3d3d745d65b38edbc73d1de8b280"
                       "7f7820221a6c3937faab19fcbb75d3c8"
                       "aaf4b63f2714cfc94e95ae43d65f6df4"
                       "3815efc214ec66a5d1be185d855a6260"
                       "141ffd179bc980490f8a26d8215dd2ab")
    ct = bytes.fromhex("e9513e8892a09085bee29c358014afd6"
                       "0d7578d21e00a31e5d61b965c18778eb"
                       "e18469170794e5ddf24aa777c8ab0a2c"
                       "62474109e617978bcc5ce3456ddd9622"
                       "833420443c2a26b1b6e20a05c189da6c")
    assert crypto.DES(key, crypto.MODE_CBC, iv).encrypt(pt) == ct
    assert crypto.DES(key, crypto.MODE_CBC, iv).decrypt(ct) == pt


def test_des_cbc_mac():
    msg = bytes.fromhex("29EE4CC8D57E49F2000943BE60D338C0")
    key = bytes.fromhex("4BEAEF3B620B3E8F864BBF365FB42885")
    assert crypto.DES.cbc_mac(key, msg) == bytes.fromhex("3D401EE6AB3F4851")
    msg = bytes.fromhex("000943BE60D338C029EE4CC8D57E49F2")
    assert crypto.DES.cbc_mac(key, msg) == bytes.fromhex("63BCBE99397C7AF7")


def test_des_cbc_mac_single():
    msg = bytes.fromhex("848200001063BCBE99397C7AF7")
    key = bytes.fromhex("D85E62A5C2C1CE12AB47794BA1E8D5C7")
    assert (crypto.DES.cbc_mac_single(key, msg) ==
            bytes.fromhex("12C8F93E06A2C86A"))
    msg = bytes.fromhex("8482010010BCC41C65CCE079CB")
    key = bytes.fromhex("7A227D376A9DBE23AB50B7DCB45B2093")
    assert (crypto.DES.cbc_mac_single(key, msg) ==
            bytes.fromhex("BDD151B575990774"))
