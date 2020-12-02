#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tool for operation with JavaCard IJC applet files"""

__author__ = "Mike Tolkachev <contact@miketolkachev.dev>"
__copyright__ = "Copyright 2020 Crypto Advance GmbH. All rights reserved"
__version__ = "1.0.0"

import os
import zipfile
import click

# Extended component tags used to store selected metadata - NON-STANDARD!
_extended_tags = {
    'dap.rsa.sha1': 0xe0,
    'dap.rsa.sha256': 0xe1
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
    9: 'ReferenceLocation',
    10: 'Export',
    11: 'Descriptor',
    12: 'Deubg',
    **{v: k for k, v in _extended_tags.items()}
}


@click.group()
@click.version_option(__version__, message="%(version)s")
def cli():
    """Tool for operation with JavaCard IJC applet files"""


@cli.command()
@click.argument(
    'cap_file',
    required=True,
    type=click.STRING,
    metavar='<cap_file_name>'
)
@click.argument(
    'ijc_file',
    required=True,
    type=click.File('wb'),
    metavar='<ijc_file_name>'
)
def convert(cap_file, ijc_file):
    """Converts CAP file to IJC format"""

    if not zipfile.is_zipfile(cap_file):
        raise click.ClickException(f"Not a valid CAP file: {cap_file}")

    ijc_data = bytearray()
    try:
        zip = zipfile.ZipFile(cap_file, 'r')
        for entry in zip.namelist():
            fname = os.path.basename(entry).lower()
            if fname.endswith(".cap") and "debug" not in fname:
                data = zip.read(entry)
                ijc_data.extend(data)
            elif fname in _extended_tags:
                data = zip.read(entry)
                item = cap_item(_extended_tags[fname], data)
                ijc_data.extend(item)
    except:
        raise click.ClickException(f"Error while parsing: {cap_file}")

    if not len(ijc_data):
        raise click.ClickException(f"The file {cap_file} has no needed data")
    ijc_file.write(ijc_data)


def cap_item(tag, data):
    """Creates a new CAP item"""

    if len(data) > 0xffff:
        raise ValueError("Data is too long")
    return bytes([tag, len(data) >> 8, len(data) & 0xff]) + data


@cli.command()
@click.argument(
    'ijc_file',
    required=True,
    type=click.File('rb'),
    metavar='<ijc_file_name>'
)
@click.option(
    '--data', '-d', 'dump_data',
    help='Enables dumping of item\'s data.',
    is_flag=True
)
def dump(ijc_file, dump_data):
    """Dumps information from IJC file"""

    data = ijc_file.read()
    idx = 0
    while idx < len(data):
        if len(data) - idx < 3:
            raise click.ClickException(f"Error while parsing: {ijc_file.name}")
        tag, size = (data[idx], data[idx+1] << 8 | data[idx+2])
        if idx + 3 + size > len(data):
            raise click.ClickException(f"Error while parsing: {ijc_file.name}")
        item_data = data[idx + 3: idx + 3 + size]
        idx += 3 + size
        assert len(item_data) == size
        try:
            dump_item(tag, item_data, dump_data)
        except:
            raise click.ClickException(f"Error while parsing: {ijc_file.name}")


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


if __name__ == '__main__':
    cli()
