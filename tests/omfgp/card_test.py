import pytest
from omfgp.card import *


def test_parse_apdu():
    res = parse_apdu(bytes.fromhex("00A4040000"))
    assert (res.cla == 0x00 and res.ins == 0xA4 and res.p1 == 0x04 and
            res.p2 == 0x00 and res.lc == 0 and res.data == b'')
    res = parse_apdu(bytes.fromhex("84F280020A4F004C4C51B5DFA7A181"))
    assert (res.cla == 0x84 and res.ins == 0xF2 and res.p1 == 0x80 and
            res.p2 == 0x02 and res.lc == 10 and
            res.data == bytes.fromhex("4F004C4C51B5DFA7A181"))

    ref_apdu_obj = APDU(0x84, 0xF2, 0x80, 0x02, 10, bytes.fromhex(
        "4F004C4C51B5DFA7A181"))
    assert parse_apdu(ref_apdu_obj) == ref_apdu_obj
    assert parse_apdu("84F280020A4F004C4C51B5DFA7A181") == ref_apdu_obj
    assert parse_apdu((0x84, 0xF2, 0x80, 0x02, 10, bytes.fromhex(
        "4F004C4C51B5DFA7A181"))) == ref_apdu_obj

    with pytest.raises(ValueError):
        # APDU is too short
        parse_apdu(bytes.fromhex("00A40400"))
    with pytest.raises(ValueError):
        # Invalid length
        parse_apdu(bytes.fromhex("84F280020B4F004C4C51B5DFA7A181"))


def test_code_apdu():
    assert code_apdu("00A4040000") == bytes.fromhex("00A4040000")
    assert code_apdu((0x00, 0xA4, 0x04, 0x00, 0, b'')) == bytes.fromhex(
        "00A4040000")
    assert code_apdu(APDU(0x00, 0xA4, 0x04, 0x00, 0, b'')) == bytes.fromhex(
        "00A4040000")

    apdu_obj = APDU(0x84, 0xF2, 0x80, 0x02, 10, bytes.fromhex(
        "4F004C4C51B5DFA7A181"))
    assert code_apdu(apdu_obj) == bytes.fromhex(
        "84F280020A4F004C4C51B5DFA7A181")
