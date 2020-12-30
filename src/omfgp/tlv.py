"""BER-TLV encoder and decoder"""

from io import BytesIO
from .util import bytes_to_int_big_endian

# TODO: move to other place
TAGS = {
    (0x6f, 0x84): "ISD AID",  # Issuer security domain applet ID
    (0x6f, 0xa5): None,  # unknown

}

# "Constructed data object" flag, if set the object has children
_TAG_CONSTRUCTED_BIT = 0b100000
# Bit pattern indicating more tag byte(s), used in the first byte only
_TAG0_EXTENDED = 0b11111
# Bit pattern indicating more tag byte(s), used in the non-first byte(s) only
_TAGN_EXTENDED = 0b10000000


def _read_tag(io_obj: BytesIO):
    """Reads tag value from a BER-TLV stream"""
    b = io_obj.read(1)
    if len(b) == 0:
        return (None, False)
    tag = b[0]
    flag_constructed = bool(tag & _TAG_CONSTRUCTED_BIT)
    if (tag & _TAG0_EXTENDED) == _TAG0_EXTENDED:
        while True:
            b = io_obj.read(1)
            if len(b) == 0:
                raise RuntimeError("Not TLV, can't read tag")
            tag = tag << 8 | b[0]
            if (b[0] & _TAGN_EXTENDED) != _TAGN_EXTENDED:
                break
    return (tag, flag_constructed)


def _read_length(io_obj: BytesIO):
    """Reads length value from a BER-TLV stream"""
    # Read first length byte
    b = io_obj.read(1)
    if len(b) == 0:
        raise RuntimeError("Not TLV, can't read length")
    if b[0] <= 0x7f:
        return b[0]

    # Read remaining length bytes
    rm_bytes = b[0] & 0b1111111
    if not (1 <= rm_bytes <= 3):
        raise RuntimeError("Not TLV, can't read length")
    b = io_obj.read(rm_bytes)
    if len(b) != rm_bytes:
        raise RuntimeError("Not TLV, can't read length")

    return bytes_to_int_big_endian(b)


def _serialize_tag(tag: int):
    """Serializes tag to bytes"""
    if tag <= 0xff:
        return bytes([tag])
    elif tag <= 0xffff:
        return bytes([tag >> 8, tag & 0xff])
    elif tag <= 0xffffff:
        return bytes([tag >> 16, (tag >> 8) & 0xff, tag & 0xff])
    raise RuntimeError("Unsupported TLV tag")


def _serialize_length(length: int):
    """Serializes length to bytes"""
    if length <= 0x7f:
        return bytes([length])
    elif length <= 0xff:
        return bytes([0x81, length])
    elif length <= 0xffff:
        return bytes([0x82, length >> 8, length & 0xff])
    elif length <= 0xffffff:
        return bytes([0x83, length >> 16, (length >> 8) & 0xff, length & 0xff])
    raise RuntimeError("Unsupported TLV length")


class TLV(dict):
    """BER-TLV object"""
    @classmethod
    def deserialize(cls, b):
        """Deserializes bytes to BER-TLV object"""
        s = BytesIO(b)
        o = cls()
        while True:
            tag, flag_constructed = _read_tag(s)
            if tag is None:
                break
            length = _read_length(s)
            v = s.read(length)
            if len(v) != length:
                raise RuntimeError("Not TLV, can't read value")
            if flag_constructed:
                v = TLV.deserialize(v)
            if tag in o:
                # Merge identical tags into list
                v_prev = o[tag]
                if isinstance(v_prev, list):
                    v_prev.append(v)
                else:
                    o[tag] = [o[tag], v]
            else:
                o[tag] = v
        return o

    def serialize(self):
        """Serializes BER-TLV object to bytes"""
        res = b''
        for tag in self.keys():
            value = self[tag]
            if isinstance(value, TLV):
                value = value.serialize()
            elif isinstance(value, dict):
                value = TLV(value).serialize()

            if isinstance(value, list):
                for subv in value:
                    res += (_serialize_tag(tag) +
                            _serialize_length(len(subv)) + subv)
            else:
                res += (_serialize_tag(tag) + _serialize_length(len(value)) +
                        value)
        return res
