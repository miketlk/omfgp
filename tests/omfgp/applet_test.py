from io import BytesIO
import pytest
import random
import hashlib
from omfgp.applet import *


def test_header():
    stream = BytesIO(bytes.fromhex("decaffed010204000005b00b5111ca"))
    hdr = Header.read_from(stream)
    assert (hdr.cap_major_ver, hdr.cap_minor_ver) == (2, 1)
    assert (hdr.package_major_ver, hdr.package_minor_ver) == (0, 0)
    assert hdr.package_aid == bytes.fromhex("B00B5111CA")
    assert hdr.package_name == ""
    assert isinstance(str(hdr), str) and len(str(hdr)) > 0
    assert isinstance(repr(hdr), str) and len(repr(hdr)) > 0


def test_header_including_name():
    stream = BytesIO(bytes.fromhex("decaffed020104fefd05b00b5111ca0474657374"))
    hdr = Header.read_from(stream)
    assert (hdr.cap_major_ver, hdr.cap_minor_ver) == (1, 2)
    assert (hdr.package_major_ver, hdr.package_minor_ver) == (253, 254)
    assert hdr.package_aid == bytes.fromhex("B00B5111CA")
    assert hdr.package_name == "test"


def test_header_fail():
    with pytest.raises(RuntimeError):
        stream = BytesIO(bytes.fromhex("decaffed0102040000"))
        _ = Header.read_from(stream)
    with pytest.raises(RuntimeError):
        stream = BytesIO(bytes.fromhex("decaffed010204000005b00b5111"))
        _ = Header.read_from(stream)
    with pytest.raises(RuntimeError):
        stream = BytesIO(bytes.fromhex("decaffed020104fefd05b00b5111ca04"))
        _ = Header.read_from(stream)
    with pytest.raises(RuntimeError):
        stream = BytesIO(bytes.fromhex("decaffed020104fefd05b00b5111ca0474"
                                       "6573"))
        _ = Header.read_from(stream)


def test_applet():
    applet = Applet.read_from(BytesIO(ref_applet_bytes))
    assert len(applet) == len(ref_load_data)
    assert applet.package_aid == bytes.fromhex("B00B5111CA")
    assert applet.applet_aid_list == [bytes.fromhex("B00B5111CA01")]
    cap_ver = (applet.header.cap_major_ver, applet.header.cap_minor_ver)
    assert cap_ver == (2, 1)
    package_ver = (applet.header.package_major_ver,
                   applet.header.package_minor_ver)
    assert package_ver == (0, 0)
    assert applet.header.package_name == ""
    assert isinstance(str(applet), str) and len(str(applet)) > 0
    assert isinstance(repr(applet), str) and len(repr(applet)) > 0


def test_applet_fail():
    with pytest.raises(RuntimeError):
        _ = Applet.read_from(BytesIO(ref_applet_bytes[1:]))
    with pytest.raises(RuntimeError):
        _ = Applet.read_from(BytesIO(ref_applet_bytes[:-1]))


def test_applet_get_data():
    applet = Applet.read_from(BytesIO(ref_applet_bytes))
    assert applet.get_data() == ref_load_data
    assert len(applet.get_data()) == len(applet)
    assert applet.get_data(0, 11) == ref_load_data[0: 11]
    assert applet.get_data(3, 11) == ref_load_data[3: 3 + 11]
    assert applet.get_data(57, 721) == ref_load_data[57: 57 + 721]
    assert applet.get_data(321, 277) == ref_load_data[321: 321 + 277]
    # Run 1000 additional tests fetching data with random offset and size
    random.seed(1)
    for i in range(1000):
        off = random.randrange(0, len(applet) - 2)
        size = random.randrange(1, len(applet) - off - 1)
        assert applet.get_data(off, size) == ref_load_data[off: off + size]


def test_applet_get_metadata():
    applet = Applet.read_from(BytesIO(ref_applet_bytes))
    assert applet.get_metadata() == ref_metadata
    assert applet.get_metadata('dap.rsa.sha1') == ref_metadata['dap.rsa.sha1']
    assert applet.get_metadata(
        'dap.rsa.sha256') == ref_metadata['dap.rsa.sha256']


def test_applet_hash():
    applet = Applet.read_from(BytesIO(ref_applet_bytes))
    assert applet.hash(hashlib.sha1()) == bytes.fromhex(
        "9265cb2a48c25459b8a953e73e838cc346fe820e")
    assert applet.hash(hashlib.sha256()) == bytes.fromhex(
        "e45503ea1dfce6dad09fb40d81568d8668aaa752477e102014cd99875a1e634f")


def test_applet_bundle():
    file = open("tests/omfgp/bundle.ijc", "rb")
    applet = Applet.read_from(file)
    assert len(applet) == 12456
    assert applet.package_aid == bytes.fromhex("B00B5111CF")
    assert applet.applet_aid_list == [
        bytes.fromhex("B00B5111CF01"), bytes.fromhex("B00B5111CF02"),
        bytes.fromhex("B00B5111CF03"), bytes.fromhex("B00B5111CF04"),
        bytes.fromhex("B00B5111CF05")]
    assert applet.hash(hashlib.sha1()) == bytes.fromhex(
        "3c6a44e4ce9f52bd1fc55333298c8a5fabfeb21a")
    assert applet.hash(hashlib.sha256()) == bytes.fromhex(
        "3233284a0eca951cd87e6fb0de6f373cc7c13d4601bc97ccfa91b3bc51e8000e")


# Reference applet as bytes, components are intentionally shuffled
ref_applet_bytes = bytes.fromhex(
    "02001f000f001f000a00150072002401fc000a003b000001130000000"
    "000000201000701fc000220188c000418038900180389011d63081167"
    "008d000d181d8901181d900b87027a05401faf016f081167008d000d1"
    "88b0005191ead02031f8d00063b181f8900af00780110ad02770110af"
    "00780110af01780410ad0203af01038d00073b180389007a053018661"
    "9189265158f00083d8c0009181d0441181d258b000a700c8f00083d8c"
    "00098b000b7a0411188c000c18018703188f000e3d1100fe8c000f870"
    "31020900b3d031049383d041020383d051061383d06106d383d071020"
    "383d081061383d10061020383d10071074383d10081065383d1009106"
    "1383d100a1070383d100b106f383d100c1074383d100d1020383d100e"
    "1067383d100f1069383d1010106d383d1011106d383d10121065383d1"
    "0131020383d10141073383d1015106f383d1016106d383d1017106538"
    "3d10181020383d10191074383d101a1065383d101b1061383d101c102"
    "0383d101d1070383d101e106c383d101f107a382cad03190319928b00"
    "103b7a0221188b001160037a198b00122d198b00133b1a032510b06a0"
    "8116e008d000d1a042575001b0002ffa1000dffa2001418198b001470"
    "0f18198b00157008116d008d000d7a0422198b00122d031a07258d001"
    "6321f1100fe6f081167008d000dad031a081f8b00103b18198b00147a"
    "0420198b00173b19ad038b00188b001919ad038b001a03ad038b00188"
    "b001b7a03000a0106b00b5111ca01006501000fdecaffed0102040000"
    "05b00b5111ca04001502000107a0000000620001050107a0000000620"
    "1010600240080000300010105000000230045004a004f005400810301"
    "000107030000016d01b201dc08000a0000000000000000000009003b0"
    "0150a040d0606100a02050505050309320dc16b170906002205111804"
    "092212040a050403070807ca0807050e15070807080d0806070703060"
    "603050072001c02000001020000020200000002001400068000000300"
    "00050681100106811003010014000600008c038103020381030106810"
    "300068107010100000006000001030000010381030303810a0103810a"
    "0603001409030014080681100503810a070300000303810a090300000"
    "203810a05e00080aa934459cbf5ece484dcd242b7ee33d5162b374a57"
    "551e811f392162c550f61364a5ad475e810816021ea2e7a14cdc7a4b7"
    "bd60cfa0dec75b12b40bae12bcf3e7c9fdbef3fe8275de2029318af17"
    "3c75dc481220653304f1ce58328526587c5e7f2fd7787fe9d7a479678"
    "ffa9800c9719ec276fb5a33d0ab680bb0d3da6c5ab4e100800b4d59c2"
    "1d2be5b90c6052b3571039ecb99bcff24decdbf3560b6a995acca9b0c"
    "38471eb245050e4b30aa941e9e7201dd7515913ff7ae785612a68c64a"
    "09d825efeb4bcdefafedc067a7b3eb67f3af49e65f879c1b72efb7345"
    "cdb97053580be1c89c83820590295d97671e596ece55d9f7fc1d6d8a4"
    "234771bede707fada8b3"
)

# Load data recovered from the applet
ref_load_data = bytes.fromhex(
    "01000fdecaffed010204000005b00b5111ca02001f000f001f000a001"
    "50072002401fc000a003b000001130000000000000201000400150200"
    "0107a0000000620001050107a000000062010103000a0106b00b5111c"
    "a0100650600240080000300010105000000230045004a004f00540081"
    "0301000107030000016d01b201dc0701fc000220188c0004180389001"
    "80389011d63081167008d000d181d8901181d900b87027a05401faf01"
    "6f081167008d000d188b0005191ead02031f8d00063b181f8900af007"
    "80110ad02770110af00780110af01780410ad0203af01038d00073b18"
    "0389007a0530186619189265158f00083d8c0009181d0441181d258b0"
    "00a700c8f00083d8c00098b000b7a0411188c000c18018703188f000e"
    "3d1100fe8c000f87031020900b3d031049383d041020383d051061383"
    "d06106d383d071020383d081061383d10061020383d10071074383d10"
    "081065383d10091061383d100a1070383d100b106f383d100c1074383"
    "d100d1020383d100e1067383d100f1069383d1010106d383d1011106d"
    "383d10121065383d10131020383d10141073383d1015106f383d10161"
    "06d383d10171065383d10181020383d10191074383d101a1065383d10"
    "1b1061383d101c1020383d101d1070383d101e106c383d101f107a382"
    "cad03190319928b00103b7a0221188b001160037a198b00122d198b00"
    "133b1a032510b06a08116e008d000d1a042575001b0002ffa1000dffa"
    "2001418198b0014700f18198b00157008116d008d000d7a0422198b00"
    "122d031a07258d0016321f1100fe6f081167008d000dad031a081f8b0"
    "0103b18198b00147a0420198b00173b19ad038b00188b001919ad038b"
    "001a03ad038b00188b001b7a08000a000000000000000000000500720"
    "01c020000010200000202000000020014000680000003000005068110"
    "0106811003010014000600008c0381030203810301068103000681070"
    "10100000006000001030000010381030303810a0103810a0603001409"
    "030014080681100503810a070300000303810a090300000203810a050"
    "9003b00150a040d0606100a02050505050309320dc16b170906002205"
    "111804092212040a050403070807ca0807050e15070807080d0806070"
    "703060603")

# Metadata coming with the applet
ref_metadata = {
    'dap.rsa.sha1': bytes.fromhex(
        "aa934459cbf5ece484dcd242b7ee33d5162b374a57551e811f392162c550f613"
        "64a5ad475e810816021ea2e7a14cdc7a4b7bd60cfa0dec75b12b40bae12bcf3e"
        "7c9fdbef3fe8275de2029318af173c75dc481220653304f1ce58328526587c5e"
        "7f2fd7787fe9d7a479678ffa9800c9719ec276fb5a33d0ab680bb0d3da6c5ab4"),
    'dap.rsa.sha256': bytes.fromhex(
        "0b4d59c21d2be5b90c6052b3571039ecb99bcff24decdbf3560b6a995acca9b0"
        "c38471eb245050e4b30aa941e9e7201dd7515913ff7ae785612a68c64a09d825"
        "efeb4bcdefafedc067a7b3eb67f3af49e65f879c1b72efb7345cdb97053580be"
        "1c89c83820590295d97671e596ece55d9f7fc1d6d8a4234771bede707fada8b3")}
