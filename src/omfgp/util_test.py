import pytest
from .util import *


def test_aid_to_str():
    assert aid_to_str(b'\x00') == "0"
    assert aid_to_str(b'\x0a') == "A"
    assert aid_to_str(b'\xa0') == "A0"
    assert aid_to_str(b'\x0a\x00') == "A00"
    assert aid_to_str(b'\xa0\x00') == "A000"
    assert aid_to_str(b'\x12\x34\x5a\xbc\xde\xf0') == "12345ABCDEF0"