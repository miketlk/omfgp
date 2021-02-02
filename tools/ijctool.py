#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tool for operation with JavaCard IJC applet files"""

__author__ = "Mike Tolkachev <contact@miketolkachev.dev>"
__copyright__ = "Copyright 2020 Crypto Advance GmbH. All rights reserved"
__version__ = "1.0.0"

import os
import zipfile
import hashlib
import click

# Extended component tags used to store selected metadata - NON-STANDARD!
_extended_tags = {
    'dap.rsa.sha1': 0xe0,
    'dap.rsa.sha256': 0xe1,
    'dap.p256.sha1': 0xe2,
    'dap.p256.sha256': 0xe3
}

# Tag names
_tag_names = {
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
    **{v: k for k, v in _extended_tags.items()}
}

# A set of items loaded in the JavaCard in the right order
_load_list = ['Header', 'Directory', 'Import', 'Applet', 'Class', 'Method',
              'StaticField', 'Export', 'ConstantPool', 'RefLocation']


@ click.group()
@ click.version_option(__version__, message="%(version)s")
def cli():
    """Tool for operation with JavaCard IJC applet files"""


@ cli.command()
@ click.argument(
    'cap_file',
    required=True,
    type=click.STRING,
    metavar='<cap_file_name>'
)
@ click.argument(
    'ijc_file',
    required=True,
    type=click.File('wb'),
    metavar='<ijc_file_name>'
)
@ click.option(
    '--no-metadata', 'no_metadata',
    help='Excludes metadata from produced IJC file (making it 100%% standard).',
    is_flag=True
)
def convert(cap_file, ijc_file, no_metadata):
    """Converts CAP file to IJC format"""

    if not zipfile.is_zipfile(cap_file):
        raise click.ClickException(f"Not a valid CAP file: {cap_file}")

    items = {}
    metadata = bytearray()
    try:
        zip = zipfile.ZipFile(cap_file, 'r')
        for entry in zip.namelist():
            tag_name = os.path.basename(entry).removesuffix(".cap")
            if tag_name in _load_list:
                data = zip.read(entry)
                items[tag_name] = data
            elif tag_name in _extended_tags:
                data = zip.read(entry)
                item = cap_item(_extended_tags[tag_name], data)
                metadata.extend(item)
    except:
        raise click.ClickException(f"Error while parsing: {cap_file}")

    if not items:
        raise click.ClickException(f"The file {cap_file} has no needed data")

    ijc_data = bytearray()
    for tag_name in _load_list:
        ijc_data.extend(items.get(tag_name, b''))
    if not no_metadata:
        ijc_data.extend(metadata)
    ijc_file.write(ijc_data)


def cap_item(tag, data):
    """Creates a new CAP item"""

    if len(data) > 0xffff:
        raise ValueError("Data is too long")
    return bytes([tag, len(data) >> 8, len(data) & 0xff]) + data


@ cli.command()
@ click.argument(
    'ijc_file',
    required=True,
    type=click.File('rb'),
    metavar='<ijc_file_name>'
)
@ click.option(
    '--data', 'dump_data',
    help='Enables dumping of item\'s data.',
    is_flag=True
)
def dump(ijc_file, dump_data):
    """Dumps information from IJC file"""

    data = ijc_file.read()
    load_items = {}
    idx = 0
    while idx < len(data):
        if len(data) - idx < 3:
            raise click.ClickException(f"Error while parsing: {ijc_file.name}")
        tag, size = (data[idx], data[idx+1] << 8 | data[idx+2])
        if idx + 3 + size > len(data):
            raise click.ClickException(f"Error while parsing: {ijc_file.name}")
        item_data = data[idx + 3: idx + 3 + size]
        assert len(item_data) == size
        try:
            dump_item(tag, item_data, dump_data)
        except:
            raise click.ClickException(f"Error while parsing: {ijc_file.name}")
        tag_name = _tag_names.get(tag, '')
        if tag_name in _load_list:
            load_items[tag_name] = data[idx: idx + 3 + size]
        idx += 3 + size

    load_data = bytearray()
    for tag_name in _load_list:
        load_data.extend(load_items.get(tag_name, b''))

    print(f"Load file size: {len(load_data)}")
    if dump_data:
        print(f"  {load_data.hex()} \n")
    print("SHA-1:  ", hash_hex('sha1', load_data))
    print("SHA-256:", hash_hex('sha256', load_data))


def dump_item(tag, data, dump_data=False):
    """Dumps one CAP/IJC item"""

    name = _tag_names.get(tag, '<unknown>')
    print(f"{name}, size: {len(data)}")
    if name in _dump_functions:
        _dump_functions[name](data)

    if dump_data:
        print(f"  {data.hex()} \n")


def dump_header(data):
    """Dumps header item"""

    magic = int.from_bytes(data[:4], byteorder='big')
    if magic != 0xdecaffed:
        raise click.ClickException(f"Incorrect header component")
    package_info = data[7:]
    aid_len = package_info[2]
    aid_bytes = package_info[3: 3 + aid_len]
    print(f"  Package-AID: '{aid_bytes.hex().upper()}'")


def dump_applet(data):
    """Dumps applet item"""

    count = data[0]
    idx = 1
    for app_idx in range(count):
        aid_len = data[idx]
        if idx + 3 + aid_len > len(data):
            raise ValueError("Incorrect applet component")
        aid_bytes = data[idx + 1: idx + 1 + aid_len]
        idx += 3 + aid_len
        print(f"  Applet-AID: '{aid_bytes.hex().upper()}'")


# Mapping of dump function to tags (in text format)
_dump_functions = {
    'Header': dump_header,
    'Applet': dump_applet
}


def hash_hex(algo, data):
    """Returns hexadecimal hash code calculated over the data using the given
    algorithm.
    """

    inst = hashlib.new(algo)
    inst.update(data)
    return inst.hexdigest()


if __name__ == '__main__':
    cli()
