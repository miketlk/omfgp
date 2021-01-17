"""Wrapper for JavaCard applet data"""

from io import BytesIO
from collections import namedtuple
from .util import AID

# Extended component tags used to store selected metadata - NON-STANDARD!
_EXTENDED_TAGS = {
    'dap.rsa.sha1': 0xe0,
    'dap.rsa.sha256': 0xe1,
    'dap.p256.sha1': 0xe2,
    'dap.p256.sha256': 0xe3
}

# Tag names
_TAG_NAMES = {
    1: 'Header',
    2: 'Directory',
    3: 'Applet',
    4: 'Import',
    5: 'ConstantPool',
    6: 'Class',
    7: 'Method',
    8: 'StaticField',
    9: 'RefLocation',
    10: 'Export',
    11: 'Descriptor',
    12: 'Deubg',
    **{v: k for k, v in _EXTENDED_TAGS.items()}
}

# A set of items loaded in the JavaCard in the right order
_LOAD_LIST = ['Header', 'Directory', 'Import', 'Applet', 'Class', 'Method',
              'StaticField', 'Export', 'ConstantPool', 'RefLocation']

# Size of tag-length prefix in bytes
_TL_SIZE = 3
# Magic word contained in header
_HDR_MAGIC_BYTES = b'\xde\xca\xff\xed'

# CAP item record, storing its size and offset inside unordered data block
_CapItem = namedtuple('CapItem', ['size', 'offset'])


class Header:
    """Header item"""
    @classmethod
    def read_from(cls, stream):
        """Reads header from a stream"""
        obj = cls()
        try:
            magic = stream.read(len(_HDR_MAGIC_BYTES))
            if magic != _HDR_MAGIC_BYTES:
                raise RuntimeError("Wrong applet format")
            obj.cap_minor_ver = (stream.read(1))[0]
            obj.cap_major_ver = (stream.read(1))[0]
            _ = stream.read(1)  # flags
            obj.package_minor_ver = (stream.read(1))[0]
            obj.package_major_ver = (stream.read(1))[0]
            aid_len = (stream.read(1))[0]
            obj.package_aid = AID(stream.read(aid_len))
            if not len(obj.package_aid) or len(obj.package_aid) != aid_len:
                raise RuntimeError("Wrong applet format")
            name_len_byte = stream.read(1)
            if len(name_len_byte):
                name_len = name_len_byte[0]
                obj.package_name = stream.read(name_len).decode()
                if len(obj.package_name) != name_len:
                    raise RuntimeError("Wrong applet format")
            else:
                obj.package_name = ""
        except:
            raise RuntimeError("Wrong applet format")
        return obj

    def __str__(self):
        s = "CAP v%d.%d, Package: '%s' %s v%d.%d" % (
            self.cap_major_ver, self.cap_minor_ver,
            self.package_name, str(self.package_aid),
            self.package_major_ver, self.package_minor_ver)
        return s

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, str(self))


class Applet:
    """Wrapper for JavaCard applet data"""
    @classmethod
    def read_from(cls, stream):
        """Reads applet from a stream of CAP components (e.g. IJC file)"""
        obj = cls()
        obj._data = stream.read()
        obj._item_table = {}
        obj._tot_size = 0
        idx = 0
        while idx < len(obj._data):
            if len(obj._data) - idx < _TL_SIZE:
                raise RuntimeError("Wrong applet format")
            tag = obj._data[idx]
            if tag == 0:
                raise RuntimeError("Wrong applet format")
            size = obj._data[idx+1] << 8 | obj._data[idx+2]
            if idx + _TL_SIZE + size > len(obj._data):
                raise RuntimeError("Wrong applet format")
            if tag in _TAG_NAMES:
                tag_name = _TAG_NAMES[tag]
                obj._item_table[tag_name] = _CapItem(size=size + _TL_SIZE,
                                                     offset=idx)
                if tag_name in _LOAD_LIST:
                    obj._tot_size += size + _TL_SIZE
            idx += _TL_SIZE + size
        obj._header = obj._parse_header_item()
        obj._applet_aid_list = obj._parse_applet_item()
        return obj

    def _parse_header_item(self):
        """Parses 'Header' component returning decoded header"""
        item = self._item_table.get('Header')
        if item is None:
            RuntimeError("Wrong applet format")
        stream = BytesIO(self._data[item.offset + _TL_SIZE:
                                    item.offset + item.size])
        return Header.read_from(stream)

    def _parse_applet_item(self):
        """Parses 'Applet' component returning a list of applet AID"""
        item = self._item_table.get('Applet')
        if item is None:
            RuntimeError("Wrong applet format")
        stream = BytesIO(self._data[item.offset + _TL_SIZE:
                                    item.offset + item.size])
        aid_list = []
        try:
            count = (stream.read(1))[0]
            for i in range(count):
                aid_len = (stream.read(1))[0]
                aid = stream.read(aid_len)
                if len(aid) != aid_len:
                    RuntimeError("Wrong applet format")
                _ = stream.read(2)  # install_method_offset
                aid_list.append(AID(aid))
        except:
            RuntimeError("Wrong applet format")
        return aid_list

    def __len__(self):
        return self._tot_size

    def get_data(self, offset: int = 0, size: int = -1):
        """Returns piece of loadable data starting from a given offset"""
        if size < 0:
            size = len(self) - offset
        if offset < 0 or size < 0:
            raise ValueError("Trying to access outside of stored data")
        if offset + size > len(self):
          size = len(self) - offset
          size = size if size >= 0 else 0
        data = bytearray()
        rm_size = size
        load_off = 0
        dst_off = offset
        for tag_name in _LOAD_LIST:
            if rm_size <= 0:
                break
            item = self._item_table.get(tag_name)
            if item is not None:
                if load_off <= dst_off <= load_off + item.size:
                    chunk_off = item.offset + (dst_off - load_off)
                    chunk_len = min(item.size - (dst_off - load_off), rm_size)
                    data += self._data[chunk_off: chunk_off + chunk_len]
                    dst_off += chunk_len
                    rm_size -= chunk_len
                load_off += item.size
        return bytes(data)

    def get_metadata(self, item_name: str = ''):
        """Returns metadata specified by item name or a full set if the name is
        not provided
        """
        if item_name:
            item = self._item_table.get(item_name)
            if item is not None:
                return self._data[item.offset + _TL_SIZE:
                                  item.offset + item.size]
            return b''
        else:
            res = {}
            for k in _EXTENDED_TAGS.keys():
                item = self._item_table.get(k)
                if item is not None:
                    res[k] = self._data[item.offset + _TL_SIZE:
                                        item.offset + item.size]
            return res

    def hash(self, hasher):
        """Returns hash of loadable data using provided hasher, e.g.
        hashlib.sha256()
        """
        for tag_name in _LOAD_LIST:
            item = self._item_table.get(tag_name)
            if item is not None:
                hasher.update(
                    self._data[item.offset: item.offset + item.size])
        return hasher.digest()

    @property
    def package_aid(self):
        return self._header.package_aid

    @property
    def applet_aid_list(self):
        return self._applet_aid_list

    @property
    def header(self):
        return self._header

    def __str__(self):
        aid_strings = [str(aid) for aid in self._applet_aid_list]
        s = "%s, Applets: [%s], Code: %dbytes" % (
            str(self._header), ", ".join(aid_strings), len(self))
        return s

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, str(self))
