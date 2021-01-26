from binascii import unhexlify as unhex
import pytest
from pytest_mock import MockerFixture
from unittest.mock import call
from omfgp.scp import *
from omfgp.scp_session import *
from omfgp.commands import *
from omfgp.status import *


def test_security_level():
    sl = SecurityLevel
    level = SecurityLevel(sl.C_DECRYPTION)
    assert level & sl.C_MAC
    level = SecurityLevel(sl.R_MAC)
    assert level & sl.C_MAC
    level = SecurityLevel(sl.R_ENCRYPTION)
    assert level & (sl.R_MAC | sl.C_DECRYPTION | sl.C_MAC)
    level = SecurityLevel(sl.CLEAR)
    assert level == sl.CLEAR


class FakeCard:
    """Rough smart card emulation"""

    def __init__(self, command_map: dict = {}, debug=False):
        self._command_map = command_map
        self.debug = debug

    def request_full(self, apdu):
        cmd = apdu[:4]
        req_data = apdu[5: 5 + apdu[4]]
        assert req_data == self._command_map[cmd][0]
        return self._command_map[cmd][1:]

    def request(self, apdu):
        data, _ = self.request_full(apdu)
        return data


def test_scp03_clear(mocker: MockerFixture):
    # Establish SCP03 connection
    # Security level: clear (no secure messaging)
    fake_card = FakeCard({
        INITIALIZE_UPDATE + b'\x00\x00': (
            unhex("2E6805A2847B9844"),
            unhex("00008048007283073469FF0300E4A2A0"
                  "7404C25B33766379EE21A55CFA"), SUCCESS),
        EXTERNAL_AUTHENTICATE + b'\x00\x00': (
            unhex("684C48D43FEDEFD990252090A826F975"), b'', SUCCESS)
    }, debug=True)
    progress_cb = mocker.stub()
    scp = open_secure_channel(
        fake_card, host_challenge=unhex("2E6805A2847B9844"),
        progress_cb=progress_cb, security_level=SecurityLevel.CLEAR,
        block_size=213)
    assert scp._VERSION == 3
    assert scp.block_size == 213
    progress_cb.assert_has_calls(
        [call(0), call(50), call(100)], any_order=False)

    # Wrap GET STATUS (0x80, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x80\x02' + card.encode("4F00")) ==
            unhex("80F28002024F00"))
    response = (unhex("E32A4F08A0000001510000009F700107"
                      "C5039EFE80C407A0000000620001CE02"
                      "0100CC08A000000151000000"), SUCCESS)
    assert scp.unwrap_response(*response) == response

    # Wrap GET STATUS (0x40, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x40\x02' + card.encode("4F00")) ==
            unhex("80F24002024F00"))
    response = (b'', b'\x6A\x88')
    assert scp.unwrap_response(*response) == response


def test_scp03_C_MAC(mocker: MockerFixture):
    # Establish SCP03 connection
    # Security level: C-MAC
    fake_card = FakeCard({
        INITIALIZE_UPDATE + b'\x00\x00': (
            unhex("68E9C8799FF8CB46"),
            unhex("00008048007283073469FF0300F8D89D"
                  "88BA1287BF9B5C9D42D5059430"), SUCCESS),
        EXTERNAL_AUTHENTICATE + b'\x01\x00': (
            unhex("F3C7624565B5894F16EF5681573C34A2"), b'', SUCCESS)
    }, debug=True)
    progress_cb = mocker.stub()
    scp = open_secure_channel(
        fake_card, host_challenge=unhex("68E9C8799FF8CB46"),
        progress_cb=progress_cb, block_size=213)
    assert scp._VERSION == 3
    assert scp.block_size == 205
    progress_cb.assert_has_calls(
        [call(0), call(50), call(100)], any_order=False)

    # Wrap GET STATUS (0x80, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x80\x02' + card.encode("4F00")) ==
            unhex("84F280020A4F004C4C51B5DFA7A181"))
    response = (unhex("E32A4F08A0000001510000009F700107"
                      "C5039EFE80C407A0000000620001CE02"
                      "0100CC08A000000151000000"), SUCCESS)
    assert scp.unwrap_response(*response) == response

    # Wrap GET STATUS (0x40, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x40\x02' + card.encode("4F00")) ==
            unhex("84F240020A4F002108D3E0BA43B673"))
    response = (b'', b'\x6A\x88')
    assert scp.unwrap_response(*response) == response

    scp.close()

    # Let's try do do something on a closed channel
    with pytest.raises(Exception):
        scp.wrap_apdu(GET_STATUS + b'\x80\x02' + card.encode("4F00"))
    with pytest.raises(Exception):
        scp.unwrap_response(*response)
    with pytest.raises(Exception):
        scp.encrypt_data(16 * '\0')


def test_scp03_C_DECRYPTION_C_MAC(mocker: MockerFixture):
    # Establish SCP03 connection
    # Security level: C-DECRYPTION, C-MAC
    fake_card = FakeCard({
        INITIALIZE_UPDATE + b'\x00\x00': (
            unhex("CC8A0407F63066E8"),
            unhex("00008048007283073469FF0300EF23AA"
                  "B4C343EDDE5B283674A8983749"), SUCCESS),
        EXTERNAL_AUTHENTICATE + b'\x03\x00': (
            unhex("112355D07180C24547A5EB3BD470F7C5"), b'', SUCCESS)
    }, debug=True)
    progress_cb = mocker.stub()
    scp = open_secure_channel(
        fake_card, host_challenge=unhex("CC8A0407F63066E8"),
        progress_cb=progress_cb,
        security_level=SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC,
        block_size=213)
    assert scp._VERSION == 3
    assert scp.block_size == 191
    progress_cb.assert_has_calls(
        [call(0), call(50), call(100)], any_order=False)

    # Wrap GET STATUS (0x80, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x80\x02' + card.encode("4F00")) ==
            unhex("84F28002184EE4C1127567676E7E0883"
                  "3B785051FD96FDFE1EC5BD293F"))
    response = (unhex(
        "E32A4F08A0000001510000009F700107C5039EFE80C407A0000000620001CE02"
        "0100CC08A000000151000000"), SUCCESS)
    assert scp.unwrap_response(*response) == response

    # Wrap GET STATUS (0x40, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x40\x02' + card.encode("4F00")) ==
            unhex("84F2400218E33CB507A6FFF09CE7A44E"
                  "EB7498295D99F96B9F2470A782"))
    response = (b'', b'\x6A\x88')
    assert scp.unwrap_response(*response) == response


def test_scp03_C_MAC_R_MAC(mocker: MockerFixture):
    # Establish SCP03 connection
    # Security level: C-MAC, R-MAC
    fake_card = FakeCard({
        INITIALIZE_UPDATE + b'\x00\x00': (
            unhex("CB6DA009E0404A67"),
            unhex("0000013628140599538231037021428D"
                  "A9468C2D5A8D05CE9657FBD5ED00001D"), SUCCESS),
        EXTERNAL_AUTHENTICATE + b'\x11\x00': (
            unhex("CC606C998B98BF8AF0746E4F50D3F65E"), b'', SUCCESS)
    }, debug=True)
    progress_cb = mocker.stub()
    scp = open_secure_channel(
        fake_card, host_challenge=unhex("CB6DA009E0404A67"),
        progress_cb=progress_cb,
        security_level=SecurityLevel.R_MAC | SecurityLevel.C_MAC,
        block_size=213)
    assert scp._VERSION == 3
    assert scp.block_size == 205
    progress_cb.assert_has_calls(
        [call(0), call(50), call(100)], any_order=False)

    # Wrap GET STATUS (0x80, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x80\x02' + card.encode("4F00")) ==
            unhex("84F280020A4F002987243A9C15F44A"))
    response = (unhex(
        "E3264F08A0000001510000009F700101C5039EFE80C407A0000001515350CC08"
        "A0000001510000007D5F8BBC66683F42"), SUCCESS)
    response_uw = (unhex(
        "E3264F08A0000001510000009F700101C5039EFE80C407A0000001515350CC08"
        "A000000151000000"), SUCCESS)
    assert scp.unwrap_response(*response) == response_uw

    # Wrap GET STATUS (0x40, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x40\x02' + card.encode("4F00")) ==
            unhex("84F240020A4F00EB20CB18E1CE889F"))
    response = (b'', b'\x6A\x88')
    assert scp.unwrap_response(*response) == response

    # Wrap GET STATUS (0x10, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x10\x02' + card.encode("4F00")) ==
            unhex("84F210020A4F00B334705EAFAB9FB1"))
    response = (unhex(
        "E3254F07A00000015153509F700101CE02FFFF8408A000000151535041CC08A0"
        "000001510000004457D7641E95465F"), SUCCESS)
    response_uw = (unhex(
        "E3254F07A00000015153509F700101CE02FFFF8408A000000151535041CC08A0"
        "00000151000000"), SUCCESS)
    assert scp.unwrap_response(*response) == response_uw


def test_scp03_C_DECRYPTION_C_MAC_R_MAC(mocker: MockerFixture):
    # Establish SCP03 connection
    # Security level: C-DECRYPTION, C-MAC, R-MAC
    fake_card = FakeCard({
        INITIALIZE_UPDATE + b'\x00\x00': (
            unhex("F70E1C5D67085E4B"),
            unhex("000001362814059953823103707B9EAD"
                  "94A8B88028F47137A2FB093F5E000021"), SUCCESS),
        EXTERNAL_AUTHENTICATE + b'\x13\x00': (
            unhex("2E2057B873FCD25D175D4D63C5CD4CEB"), b'', SUCCESS)
    }, debug=True)
    progress_cb = mocker.stub()
    scp = open_secure_channel(
        fake_card, host_challenge=unhex("F70E1C5D67085E4B"),
        progress_cb=progress_cb,
        security_level=(SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC |
                        SecurityLevel.R_MAC),
        block_size=213)
    assert scp._VERSION == 3
    assert scp.block_size == 191
    progress_cb.assert_has_calls(
        [call(0), call(50), call(100)], any_order=False)

    # Wrap GET STATUS (0x80, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x80\x02' + card.encode("4F00")) ==
            unhex("84F2800218E9170B7D79EA80AF507247"
                  "375BB3F8EDE6F54FDD858BAE89"))
    response = (unhex(
        "E3264F08A0000001510000009F700101C5039EFE80C407A0000001515350CC08"
        "A000000151000000707D9895B36C6F6B"), SUCCESS)
    response_uw = (unhex(
        "E3264F08A0000001510000009F700101C5039EFE80C407A0000001515350CC08"
        "A000000151000000"), SUCCESS)
    assert scp.unwrap_response(*response) == response_uw

    # Wrap GET STATUS (0x40, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x40\x02' + card.encode("4F00")) ==
            unhex("84F240021804B77FFA640854E3BA8611"
                  "F944C9B99F938E8E1A5FF70E98"))
    response = (b'', b'\x6A\x88')
    assert scp.unwrap_response(*response) == response

    # Wrap GET STATUS (0x10, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x10\x02' + card.encode("4F00")) ==
            unhex("84F2100218291B45B303C43B6222834B"
                  "C0011A83A91BDD0CFD8BACD09B"))
    response = (unhex(
        "E3254F07A00000015153509F700101CE02FFFF8408A000000151535041CC08A0"
        "0000015100000039B68A29F735CFCC"), SUCCESS)
    response_uw = (unhex(
        "E3254F07A00000015153509F700101CE02FFFF8408A000000151535041CC08A0"
        "00000151000000"), SUCCESS)
    assert scp.unwrap_response(*response) == response_uw


def test_scp03_C_DECRYPTION_R_ENCRYPTION_C_MAC_R_MAC(mocker: MockerFixture):
    # Establish SCP03 connection
    # Security level: C-DECRYPTION, R-ENCRYPTION, C-MAC, R-MAC
    fake_card = FakeCard({
        INITIALIZE_UPDATE + b'\x00\x00': (
            unhex("0C980267C298D194"),
            unhex("00000136281405995382310370730BE0"
                  "14C03B4558A2155798D5B2C602000023"), SUCCESS),
        EXTERNAL_AUTHENTICATE + b'\x33\x00': (
            unhex("9716680D938E0CE764738F77E5E39408"), b'', SUCCESS)
    }, debug=True)
    progress_cb = mocker.stub()
    scp = open_secure_channel(
        fake_card, host_challenge=unhex("0C980267C298D194"),
        progress_cb=progress_cb,
        security_level=(
            SecurityLevel.C_DECRYPTION | SecurityLevel.R_ENCRYPTION |
            SecurityLevel.C_MAC | SecurityLevel.R_MAC),
        block_size=250)
    assert scp._VERSION == 3
    assert scp.block_size == 239
    progress_cb.assert_has_calls(
        [call(0), call(50), call(100)], any_order=False)

    # Wrap GET STATUS (0x80, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x80\x02' + card.encode("4F00")) ==
            unhex("84F2800218AFB12C966FF538690FA041"
                  "99550D8E93AF7F2569E92DEC66"))
    response = (unhex(
        "0C7A219212D7B6E7B1F602BA291660368CA6E7C959E343FDBCDA20285A5A2A52"
        "143C8AA1ED5580A5DDB8A1D54730F461424520A6C56622FD"), SUCCESS)
    response_uw = (unhex(
        "E3264F08A0000001510000009F700101C5039EFE80C407A0000001515350CC08"
        "A000000151000000"), SUCCESS)
    assert scp.unwrap_response(*response) == response_uw

    # Wrap GET STATUS (0x40, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x40\x02' + card.encode("4F00")) ==
            unhex("84F240021851EF5596042E756C67E7A0"
                  "31A33F88C25E0F05398B4ADFBA"))
    response = (b'', b'\x6A\x88')
    assert scp.unwrap_response(*response) == response

    # Wrap GET STATUS (0x10, 0x02) and unwrap response
    assert (scp.wrap_apdu(GET_STATUS + b'\x10\x02' + card.encode("4F00")) ==
            unhex("84F2100218CEB683FB79244285024670"
                  "A969C17182CE2534871478DDA2"))
    response = (unhex(
        "123AB3A33146D67BC317E3873631F83DFC1C680D88E8147DD9CB28"
        "99433878847B911D7678CA6879E2FD674F02A778D56B563952AFA82611"), SUCCESS)
    response_uw = (unhex(
        "E3254F07A00000015153509F700101CE02FFFF8408A000000151535041CC08A0"
        "00000151000000"), SUCCESS)
    assert scp.unwrap_response(*response) == response_uw


def test_scp03_Key_DEK():
    # Establish SCP03 connection
    # Security level: clear (no secure messaging)
    fake_card = FakeCard({
        INITIALIZE_UPDATE + b'\x00\x00': (
            unhex("2E6805A2847B9844"),
            unhex("00008048007283073469FF0300E4A2A0"
                  "7404C25B33766379EE21A55CFA"), SUCCESS),
        EXTERNAL_AUTHENTICATE + b'\x00\x00': (
            unhex("684C48D43FEDEFD990252090A826F975"), b'', SUCCESS)
    }, debug=True)
    scp = open_secure_channel(
        fake_card, host_challenge=unhex("2E6805A2847B9844"),
        security_level=SecurityLevel.CLEAR)
    assert scp._VERSION == 3

    # Test sensitive data encryption and decryption with Key-DEK
    pt = unhex("8B37F9148DF4BB25956BE6310C73C8DC"
               "58EA9714FF49B643107B34C9BFF096A9"
               "4FEDD6823526ABC27A8E0B16616EEE25"
               "4AB4567DD68E8CCD4C38AC563B13639C")
    ct = unhex("014E02F68B094BE48EE05AFC1B1A14D6"
               "193BDB0EDF8171115B6643A2EA4F1459"
               "9B9EE7FB0FF02C9B7FF297E96A0F4441"
               "D5B7ABC1380A54164D39F0004D4C8016")
    assert scp.encrypt_data(pt) == ct
    assert scp.decrypt_data(ct) == pt
