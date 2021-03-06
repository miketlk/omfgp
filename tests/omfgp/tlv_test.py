from io import BytesIO
import pytest
from omfgp.tlv import *
from omfgp.tlv import _read_tag
from omfgp.tlv import _read_length
from omfgp.tlv import _serialize_tag
from omfgp.tlv import serialize_length

# Reference SECLECT response
select_response = bytes.fromhex("6f108408a000000151000000a5049f6501ff")
# Reference SECLECT response, deserialized
select_response_deserialized = {
    # File Control Information (FCI template)
    0x6f: {
        # Application / file AID
        0x84: b'\xa0\x00\x00\x01\x51\x00\x00\x00',
        # Proprietary data
        0xa5: {
            # Maximum length of data field in command message
            0x9f65: b'\xff'
        }
    }
}


def test_read_tag():
    assert _read_tag(BytesIO(b'')) == (None, False)
    assert _read_tag(BytesIO(b'\x00')) == (0x00, False)
    assert _read_tag(BytesIO(b'\x01')) == (0x01, False)
    assert _read_tag(BytesIO(b'\x20')) == (0x20, True)
    assert _read_tag(BytesIO(b'\x1f\x01')) == (0x1f01, False)
    assert _read_tag(BytesIO(b'\x1f\x80\x01')) == (0x1f8001, False)
    assert _read_tag(BytesIO(b'\x3f\x80\x01')) == (0x3f8001, True)
    with pytest.raises(RuntimeError):
        _read_tag(BytesIO(b'\x1f'))
    with pytest.raises(RuntimeError):
        _read_tag(BytesIO(b'\x1f\x80'))
    with pytest.raises(RuntimeError):
        _read_tag(BytesIO(b'\x1f\x80\x81'))


def test_read_length():
    assert _read_length(BytesIO(b'\x00')) == 0
    assert _read_length(BytesIO(b'\x01')) == 1
    assert _read_length(BytesIO(b'\x7f')) == 0x7f
    assert _read_length(BytesIO(b'\x81\x00')) == 0
    assert _read_length(BytesIO(b'\x81\x01')) == 1
    assert _read_length(BytesIO(b'\x81\xFF')) == 0xFF
    assert _read_length(BytesIO(b'\x82\x00\x00')) == 0
    assert _read_length(BytesIO(b'\x82\x12\x34')) == 0x1234
    assert _read_length(BytesIO(b'\x82\xff\xff')) == 0xffff
    assert _read_length(BytesIO(b'\x83\x00\x00\x00')) == 0
    assert _read_length(BytesIO(b'\x83\x12\x34\x56')) == 0x123456
    assert _read_length(BytesIO(b'\x83\xff\xff\xff')) == 0xffffff
    with pytest.raises(RuntimeError):
        _read_length(BytesIO(b''))
    with pytest.raises(RuntimeError):
        _read_length(BytesIO(b'\x81'))
    with pytest.raises(RuntimeError):
        _read_length(BytesIO(b'\x82\x00'))
    with pytest.raises(RuntimeError):
        _read_length(BytesIO(b'\x83\x00\x00'))


def test_deserialize():
    assert TLV.deserialize(b'\x5f\x1f\x83\x00\x00\x05Hello') == {
        0x5f1f: b'Hello'}
    assert (TLV.deserialize(b'\x01\x05Hello\x01\x05world') ==
            {0x01: [b'Hello', b'world']})
    assert TLV.deserialize(select_response) == select_response_deserialized


def test_serialize_tag():
    assert _serialize_tag(0) == b'\x00'
    assert _serialize_tag(1) == b'\x01'
    assert _serialize_tag(0x1f01) == b'\x1f\x01'
    assert _serialize_tag(0x1f8001) == b'\x1f\x80\x01'


def test_serialize_length():
    assert serialize_length(0) == b'\x00'
    assert serialize_length(1) == b'\x01'
    assert serialize_length(0x7f) == b'\x7f'
    assert serialize_length(0xff) == b'\x81\xFF'
    assert serialize_length(0x1234) == b'\x82\x12\x34'
    assert serialize_length(0xffff) == b'\x82\xff\xff'
    assert serialize_length(0x123456) == b'\x83\x12\x34\x56'
    assert serialize_length(0xffffff) == b'\x83\xff\xff\xff'


def test_lv_encode():
    assert lv_encode(b'') == b'\x00'
    assert lv_encode(b'\x55') == b'\x01\x55'
    assert lv_encode(b'\x12\x34\x56') == b'\x03\x12\x34\x56'
    assert lv_encode(0x7f * b'\xab') == b'\x7f' + 0x7f * b'\xab'
    assert lv_encode(0x80 * b'\xab') == b'\x81\x80' + 0x80 * b'\xab'
    assert lv_encode(0xff * b'\xab') == b'\x81\xff' + 0xff * b'\xab'
    assert lv_encode(0x100 * b'\xab') == b'\x82\x01\x00' + 0x100 * b'\xab'
    assert lv_encode(0xffff * b'\xab') == b'\x82\xff\xff' + 0xffff * b'\xab'
    assert lv_encode(0x10000 * b'\xab') == (b'\x83\x01\x00\x00' +
                                            0x10000 * b'\xab')
    assert lv_encode(0xffffff * b'\xab') == (b'\x83\xff\xff\xff' +
                                             0xffffff * b'\xab')


def test_serialize():
    assert TLV({0x5f1f: b'Hello'}).serialize() == b'\x5f\x1f\x05Hello'
    assert (TLV({0x01: [b'Hello', b'world']}).serialize() ==
            b'\x01\x05Hello\x01\x05world')
    assert TLV(select_response_deserialized).serialize() == select_response
