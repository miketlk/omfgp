from binascii import hexlify
from collections import namedtuple
import hashlib
from .util import *
from .gp_types import *
from . import commands
from . import status
from . import scp
from . import scp_session
from . import tlv
from . import applet

# Parsed APDU
APDU = namedtuple('APDU', ['cla', 'ins', 'p1', 'p2', 'lc', 'data'])
# Security domain or application status
SDAppStatus = namedtuple('SDAppStatus', ['aid', 'state', 'privileges', 'isp_list',
                                         'file_aid', 'sd_aid'])
# Executable load file status
FileStatus = namedtuple('FileStatus', ['aid', 'state', 'version',
                                       'module_aid_list', 'sd_aid'])

# Response to SELECT command
SelectResponse = namedtuple('SelectResponse', ['aid', 'sd_data', 'block_size'])


class ISOException(Exception):
    def __init__(self, code):
        self.code = code

    def __str__(self):
        return "0x%s '%s'" % (hexlify(self.code).decode(),
                              status.response_text(self.code))

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, str(self))


def encode(data=b''):
    # str -> hex
    if isinstance(data, str):
        data = bytes.fromhex(data)
    return bytes([len(data)])+bytes(data)


def parse_apdu(apdu) -> APDU:
    """Parse and validates APDU returning (CLA, INS, P1, P2, Lc, Data)."""
    if isinstance(apdu, APDU):
        return apdu
    elif isinstance(apdu, tuple):
        res = APDU(*apdu)
    else:
        if isinstance(apdu, str):
            apdu = bytes.fromhex(apdu)
        if len(apdu) < 5:
            raise ValueError("Invalid APDU")
        data = apdu[5:]
        res = APDU(*(tuple(apdu[:5]) + (data,)))

    if res.lc != len(res.data):
        raise ValueError("Invalid APDU")

    if res.ins == commands.GET_RESPONSE[commands.OFF_INS]:
        if res.p1 != 0 or res.p2 != 0 or res.lc != 0:
            raise ValueError("Invalid APDU")
    elif res.ins & 0xF0 in (0x60, 0x90):
        raise ValueError("Invalid APDU")

    return res


def code_apdu(apdu_obj: APDU) -> bytes:
    """Create APDU byte string from APDU named tuple or hex string."""
    if isinstance(apdu_obj, (bytes, bytearray)):
        return apdu_obj
    elif isinstance(apdu_obj, str):
        return bytes.fromhex(apdu_obj)
    elif not isinstance(apdu_obj, APDU):
        apdu_obj = APDU(*apdu_obj)

    return bytes(apdu_obj[:5]) + apdu_obj.data


class GPCard:
    def __init__(self, connection=None, reader=None, debug=False, progress_cb=None):
        if connection is None:
            connection = get_connection(reader)
        self.connection = connection
        self.debug = debug
        self.progress_cb = progress_cb
        self._scp_inst = None
        self._block_size = 256

    def transmit(self: bytes, apdu: bytes) -> tuple:
        """Raw function from pyscard module with byte string API"""
        if len(apdu) < commands.OFF_DATA:
            raise RuntimeError("Invalid APDU")
        if apdu[commands.OFF_LC] != 0:
            if apdu[commands.OFF_LC] == len(apdu) - commands.OFF_DATA:
                apdu += b'\x00'
            elif apdu[commands.OFF_LC] != len(apdu) - commands.OFF_DATA + 1:
                raise RuntimeError("Invalid APDU")
        data, *sw = self.connection.transmit(list(apdu))
        return bytes(data), bytes(sw)

    def request_full(self, apdu: bytes, ignore_errors=[]) -> tuple:
        """Make a request to smartcard returning data and status bytes."""
        if self.debug:
            print(">>", hexlify(apdu).decode())

        if self._scp_inst is None:
            data, sw = self.transmit(apdu)
        else:
            resp = self.transmit(self._scp_inst.wrap_apdu(apdu))
            data, sw = self._scp_inst.unwrap_response(*resp)

        if status.is_error(sw) and sw not in ignore_errors:
            raise ISOException(sw)
        if self.debug:
            print("<<", hexlify(data).decode(), hexlify(sw).decode())
        return data, sw

    def request(self, apdu: bytes) -> bytes:
        """Make a request to smartcard returning only data."""
        data, _ = self.request_full(apdu)
        return data

    def disconnect(self):
        """Disconnect from smart card interface."""
        self.close_secure_channel()
        self.connection.disconnect()

    def select(self, aid: bytes = b'') -> SelectResponse:
        """Select an applet by AID."""
        # Select by name first or only occurrence of an applet
        p1p2 = b'\x04\x00'
        data = self.request(commands.SELECT + p1p2 + encode(aid))
        fci = tlv.TLV.deserialize(data).get(0x6F, tlv.TLV())
        aid = AID(fci.get(0x84, b''))
        prop_data = fci.get(0xA5, tlv.TLV())
        sd_data = prop_data.get(0x73, tlv.TLV())
        self._block_size = ord(prop_data.get(0x9F65, b'\xff'))
        return SelectResponse(aid, sd_data, self._block_size)

    def get_status(self, kind: int = StatusKind.APP_SSD,
                   aid: bytes = b'') -> list:
        """Request status information from the card.

        :param aid: application AID, defaults to b''
        :param kind: kind of status information requested, defaults to
            StatusKind.APP_SD
        :return: a list of TLV decoded card responses
        """
        if kind not in StatusKind._values:
            raise ValueError("Invalid kind")

        responses = []
        p2 = GetStatusP2.TAGGED
        cdata = tlv.TLV({0x4f: aid}).serialize()
        while True:
            rdata, sw = self.request_full(
                commands.GET_STATUS + bytes([kind, p2]) + encode(cdata),
                ignore_errors=[status.ERR_NOT_FOUND])
            if sw == status.SUCCESS:
                gp_data = tlv.TLV.deserialize(rdata)
                responses.append(gp_data.get(0xE3, {}))
                break
            elif sw == status.ERR_NOT_FOUND:
                break
            elif sw != status.MORE_DATA:
                raise ISOException(sw)
            p2 |= GetStatusP2.NEXT

        status_recs = []
        for resp in responses:
            for rec in inlist(resp):
                aid = AID(rec.get(0x4F, b''))
                lc_value = ord(rec.get(0x9F70, b'\0'))
                sd_aid = AID(rec.get(0xCC, b''))
                if kind in StatusKind._file_kinds:
                    version = rec.get(0xCC, b'')
                    modules = inlist(rec.get(0x84, []))
                    modules = [AID(m) for m in modules]
                    state = FileLifeCycle(lc_value)
                    stat = FileStatus(aid, state, version, modules, sd_aid)
                else:
                    privileges = Privileges.deserialize(rec.get(0xC5, b''))
                    isp_list = inlist(rec.get(0xCF, []))
                    file_aid = AID(rec.get(0xC4, b''))
                    if 'SECURITY_DOMAIN' in privileges:
                        state = SDLifeCycle(lc_value)
                    else:
                        state = AppLifeCycle(lc_value)
                    stat = SDAppStatus(aid, state, privileges, isp_list,
                                       file_aid, sd_aid)
                status_recs.append(stat)

        return status_recs

    def _install(self, role: int, file_aid: bytes = b'',
                 sd_aid: bytes = b'', module_aid: bytes = b'',
                 app_aid: bytes = b'', data_hash: bytes = b'',
                 privileges: list = [], params: bytes = b'',
                 token: bytes = b'', process: int = InstallProcess.NONE
                 ) -> tuple:
        """Issue INSTALL command"""

        # Separate role identifier from the "more" bit
        role_id, more_bit = role & ~InstallRole.MORE, role & InstallRole.MORE

        # Pack data according to command role
        if (role_id == InstallRole.LOAD or
                (role_id == InstallRole.LOAD_INSTALL_MAKE_SELECTABLE and
                 more_bit)):
            data = (tlv.lv_encode(file_aid) + tlv.lv_encode(sd_aid) +
                    tlv.lv_encode(data_hash) + tlv.lv_encode(params) +
                    tlv.lv_encode(token))
        elif (role_id in (InstallRole.INSTALL, InstallRole.MAKE_SELECTABLE,
                          InstallRole.INSTALL_MAKE_SELECTABLE) or
              (role_id == InstallRole.LOAD_INSTALL_MAKE_SELECTABLE and
               not more_bit)):
            if not params:
                params = b'\xC9\x00'  # Application Specific Parameters
            data = (tlv.lv_encode(file_aid) + tlv.lv_encode(module_aid) +
                    tlv.lv_encode(app_aid) +
                    tlv.lv_encode(Privileges(privileges).serialize()) +
                    tlv.lv_encode(params) + tlv.lv_encode(token))
        elif role_id in (InstallRole.EXTRADITION, InstallRole.REGISTRY_UPDATE,
                         InstallRole.PERSONALIZATION):
            if app_aid and file_aid:
                raise ValueError("Only one application/file AID required")
            data = (tlv.lv_encode(sd_aid) + b'\0' +
                    tlv.lv_encode(app_aid if app_aid else file_aid) + b'\0' +
                    tlv.lv_encode(params) + tlv.lv_encode(token))
        else:
            raise ValueError("Invalid role")

        p1p2 = bytes([role, process])
        return self.request_full(commands.INSTALL + p1p2 + encode(data))

    def _load(self, data: bytes, block_num: int, last: bool = False):
        """Issue LOAD command"""
        p1p2 = bytes([LoadP1.LAST if last else 0, block_num])
        return self.request_full(commands.LOAD + p1p2 + encode(data))

    def _make_dap_block(self, applet: applet.Applet, dap_sd_aid: bytes = b''
                        ) -> tuple:
        """Make DAP block and hash of the applet."""
        md = applet.get_metadata()
        sig, hasher = None, None
        if 'dap.p256.sha256' in md:
            sig, hasher = md['dap.p256.sha256'], hashlib.sha256()
        elif 'dap.p256.sha1' in md:
            sig, hasher = md['dap.p256.sha1'], hashlib.sha1()
        elif 'dap.rsa.sha256' in md:
            sig, hasher = md['dap.rsa.sha256'], hashlib.sha256()
        elif 'dap.rsa.sha1' in md:
            sig, hasher = md['dap.rsa.sha1'], hashlib.sha1()

        if sig and hasher and dap_sd_aid:
            # Using [(k,v), (k,v) ...] initializer format to preserve key order
            block = tlv.TLV([
                (0xE2, tlv.TLV([
                    (0x4F, dap_sd_aid), (0xC3, sig)
                ]))
            ]).serialize()
            return block, applet.hash(hasher)

        return b'', b''

    def load_applet(self, applet: applet.Applet, target_sd_aid: bytes = b'',
                    dap_sd_aid: bytes = b'', privileges=[],
                    install_params=b''):
        """Load and install applet or bundle

        :param applet: applet or bundle to load
        :param target_sd_aid: AID of the target Security Domain
        :param dap_sd_aid: AID of a Security Domain for DAP verification
        :param privileges: a list of privileges, may be a dict with a list of
            privileges for each appled AID
        :param install_params: parameters passed to applet(s) during
            installation, may be a dict with a set of parameters for each
            applet AID
        """
        if self._scp_inst is None:
            raise RuntimeError("Secure channel is required")

        dap_block, hash = self._make_dap_block(applet, dap_sd_aid)
        prefix = dap_block + b'\xC4' + tlv.serialize_length(len(applet))
        data_n_bytes = len(prefix) + len(applet)
        data_blocks = -(data_n_bytes // -self._scp_inst.block_size)
        n_apdu = 1 + data_blocks + len(applet.applet_aid_list)

        progress = ProgressCallback(self.progress_cb)
        progress_inc = 100 / n_apdu
        progress(0)

        self._install(InstallRole.LOAD, file_aid=applet.package_aid,
                      sd_aid=target_sd_aid, data_hash=hash)
        progress.advance(progress_inc)

        # Load applet data combined with TLV-encoded prefix
        offset = 0
        for block_n in range(data_blocks):
            rm_size = self._scp_inst.block_size
            data = bytearray(prefix[offset: offset + rm_size])
            rm_size -= len(data)
            offset += len(data)
            if offset >= len(prefix):
                app_data = applet.get_data(offset - len(prefix), rm_size)
                data += app_data
                offset += len(app_data)
            is_last = True if (block_n == data_blocks - 1) else False
            self._load(data, block_n, is_last)
            progress.advance(progress_inc)

        # Install and make selectable all applets from the file
        for aid in applet.applet_aid_list:
            if isinstance(privileges, dict):
                app_privileges = privileges.get(aid, [])
            else:
                app_privileges = privileges
            if isinstance(install_params, dict):
                app_params = install_params.get(aid, b'')
            else:
                app_params = install_params
            app_params = tlv.TLV({0xC9: app_params}).serialize()
            self._install(InstallRole.INSTALL_MAKE_SELECTABLE,
                          file_aid=applet.package_aid, module_aid=aid,
                          app_aid=aid, privileges=app_privileges,
                          params=app_params)
            progress.advance(progress_inc)

        progress(100)

    def delete_object(self, aid: bytes, delete_related=True):
        """Delete a uniquely identifiable object and its related object(s)

        :param aid: AID of the object to delete
        :param delete_related: if true deletes related object(s) as well,
            defaults to True
        """
        if self._scp_inst is None:
            raise RuntimeError("Secure channel is required")

        p1 = DeleteP1.LAST
        p2 = (DeleteP2.OBJECT_AND_RELATED if delete_related else
              DeleteP2.OBJECT_ONLY)
        data = tlv.TLV([(0x4F, aid)]).serialize()
        self.request(commands.DELETE + bytes([p1, p2]) + encode(data))

    def open_secure_channel(self, keys: scp.StaticKeys = scp.DEFAULT_KEYS,
                            **kwargs):
        """Open secure channel using one of SCP protocols chosen by the card.

        :param keys: static keys used to derive session keys and parameters
        :param progress_cb: progress callback, invoked with percent of
            completeness (0-100) as a single argument
        :key key_version: key version, defaults to 0 (first available key)
        :key security_level: security level, a combination of scp.SecurityLevel
            constants, by defaults to only MAC in command
        :key host_challenge: host challenge override
        :key block_size: maximum allowed size of data block in bytes
        :key buggy_icv_counter: flag forcing increment of ICV counter even if
            command has no data, defaults to False
        :key min_scp_version: minimum acceptable SCP version, defaults to 0
        :key scp02_i: i-parameter for SCP02 protocol, defaults to 0x55
        """
        self.close_secure_channel()
        if 'block_size' not in kwargs:
            kwargs['block_size'] = self._block_size
        self._scp_inst = scp_session.open_secure_channel(
            self, keys=keys, progress_cb=self.progress_cb, **kwargs)

    def close_secure_channel(self):
        if self._scp_inst is not None:
            self._scp_inst.close()
            self._scp_inst = None

    @property
    def scp_version(self):
        return self._scp_inst.version if self._scp_inst is not None else None
