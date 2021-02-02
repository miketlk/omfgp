import pytest
from omfgp.gp_types import *

# The fullest set of privileges; 'dap_verification' is excluded because it
# conflicts with 'mandated_dap_verification'.
FULL_PRIVILEGES = [
    'SECURITY_DOMAIN',
    'DELEGATED_MANAGEMENT',
    'CARD_LOCK',
    'CARD_TERMINATE',
    'CARD_RESET',
    'CVM_MANAGEMENT',
    'MANDATED_DAP_VERIFICATION',
    'TRUSTED_PATH',
    'AUTHORIZED_MANAGEMENT',
    'TOKEN_MANAGEMENT',
    'GLOBAL_DELETE',
    'GLOBAL_LOCK',
    'GLOBAL_REGISTRY',
    'FINAL_APPLICATION',
    'GLOBAL_SERVICE',
    'RECEIPT_GENERATION',
    'CIPHERED_LOAD_FILE_DATA_BLOCK',
    'CONTACTLESS_ACTIVATION',
    'CONTACTLESS_SELF_ACTIVATION'
]

# The fullest set of privileges that can be coded in a single byte;
# 'dap_verification' is excluded because it conflicts with
# 'mandated_dap_verification'.
FULL_PRIVILEGES_1BYTE = [
    'SECURITY_DOMAIN',
    'DELEGATED_MANAGEMENT',
    'CARD_LOCK',
    'CARD_TERMINATE',
    'CARD_RESET',
    'CVM_MANAGEMENT',
    'MANDATED_DAP_VERIFICATION'
]


def test_Privileges_deserialize():
    assert Privileges.deserialize(b'\0') == []
    assert Privileges.deserialize(b'\0\0\0') == []
    assert (Privileges.deserialize(b'\xc0\0\0') ==
            ['SECURITY_DOMAIN', 'DAP_VERIFICATION'])
    assert (Privileges.deserialize(b'\xc0') ==
            ['SECURITY_DOMAIN', 'DAP_VERIFICATION'])
    assert (Privileges.deserialize(bytes.fromhex("C24210")) ==
            ['SECURITY_DOMAIN', 'DAP_VERIFICATION', 'CVM_MANAGEMENT',
             'AUTHORIZED_MANAGEMENT', 'FINAL_APPLICATION',
             'CONTACTLESS_SELF_ACTIVATION'])
    assert Privileges.deserialize(bytes.fromhex("FFFFF0")) == FULL_PRIVILEGES


def test_Privileges_serialize():
    assert Privileges([]).serialize(1) == b'\0'
    assert Privileges([]).serialize() == b'\0\0\0'
    assert Privileges(['DAP_VERIFICATION']).serialize(1) == b'\xc0'
    assert Privileges(['DAP_VERIFICATION']).serialize() == b'\xc0\0\0'
    assert (Privileges(['SECURITY_DOMAIN', 'DAP_VERIFICATION', 'CVM_MANAGEMENT',
                        'AUTHORIZED_MANAGEMENT', 'FINAL_APPLICATION',
                        'CONTACTLESS_SELF_ACTIVATION']).serialize() ==
            bytes.fromhex("C24210"))
    assert Privileges(FULL_PRIVILEGES).serialize() == bytes.fromhex("FFFFF0")

    with pytest.raises(ValueError):
        Privileges(
            ['DAP_VERIFICATION', 'MANDATED_DAP_VERIFICATION']).serialize()


def test_Privileges_exhaustive():
    for priv in FULL_PRIVILEGES:
        priv_lst = [] if priv == 'SECURITY_DOMAIN' else ['SECURITY_DOMAIN']
        priv_lst.append(priv)
        priv_bytes = Privileges(priv_lst).serialize()
        assert len(priv_bytes) == 3
        assert Privileges.deserialize(priv_bytes) == priv_lst

    for priv in FULL_PRIVILEGES_1BYTE:
        priv_lst = [] if priv == 'SECURITY_DOMAIN' else ['SECURITY_DOMAIN']
        priv_lst.append(priv)
        priv_bytes = Privileges(priv_lst).serialize(1)
        assert len(priv_bytes) == 1
        assert Privileges.deserialize(priv_bytes) == priv_lst


def test_FileLifeCycle():
    assert FileLifeCycle(0x01) == 0x01
    assert FileLifeCycle('LOADED') == 0x01
    assert FileLifeCycle(0x01) == FileLifeCycle(0x01)
    assert FileLifeCycle(0x01) != FileLifeCycle(0x02)
    assert FileLifeCycle('LOADED') == FileLifeCycle('LOADED')
    assert str(FileLifeCycle(0x01)) == 'LOADED'
    assert FileLifeCycle(0x01) == 'LOADED'
    assert FileLifeCycle(0x01) != 'LOADEDX'
    assert str(FileLifeCycle(123)) == '123'
    assert FileLifeCycle(0x01).in_state('LOADED')
    assert not FileLifeCycle(0x02).in_state('LOADED')
    assert FileLifeCycle('LOADED').in_state('LOADED')

    with pytest.raises(ValueError):
        FileLifeCycle('INVALID_STATE_STRING')
    with pytest.raises(ValueError):
        FileLifeCycle(-1)
    with pytest.raises(ValueError):
        FileLifeCycle(256)
    with pytest.raises(ValueError):
        FileLifeCycle('LOADED').in_state('INVALID_STATE_STRING')


def test_AppLifeCycle():
    assert AppLifeCycle(0b00000011) == 'INSTALLED'
    assert AppLifeCycle(0b00000011) == 0b00000011
    assert str(AppLifeCycle(0b00000011)) == 'INSTALLED'
    assert AppLifeCycle(0b00000111) == 'SELECTABLE'
    assert AppLifeCycle(0b00000011).in_state('INSTALLED')
    assert AppLifeCycle(0b00000111).in_state('SELECTABLE')
    for x in range(1, 15):
        assert AppLifeCycle(x << 3 | 0b00000111) == x << 3 | 0b00000111
        assert AppLifeCycle(x << 3 | 0b00000111) == ("APP_SPECIFIC%d" % x)
        assert str(AppLifeCycle(x << 3 | 0b00000111)) == ("APP_SPECIFIC%d" % x)
        assert AppLifeCycle(x << 3 | 0b00000111).in_state("APP_SPECIFIC%d" % x)
    for x in range(32):
        assert str(AppLifeCycle((x << 2) | 0b10000011)) == 'LOCKED'
        assert AppLifeCycle((x << 2) | 0b10000011).in_state('LOCKED')

    assert str(AppLifeCycle('INSTALLED')) == 'INSTALLED'
    assert str(AppLifeCycle('SELECTABLE')) == 'SELECTABLE'
    for x in range(1, 15):
        assert (str(AppLifeCycle('APP_SPECIFIC' + str(x))) ==
                ('APP_SPECIFIC' + str(x)))
    assert str(AppLifeCycle('LOCKED')) == 'LOCKED'

    assert AppLifeCycle('INSTALLED').in_state('INSTALLED')
    assert AppLifeCycle('SELECTABLE').in_state('SELECTABLE')
    for x in range(1, 15):
        lc = AppLifeCycle('APP_SPECIFIC' + str(x))
        assert lc.in_state('APP_SPECIFIC' + str(x))
    assert AppLifeCycle('LOCKED').in_state('LOCKED')

    with pytest.raises(ValueError):
        AppLifeCycle('INVALID_STATE_STRING')
    with pytest.raises(ValueError):
        AppLifeCycle(-1)
    with pytest.raises(ValueError):
        AppLifeCycle(256)
    with pytest.raises(ValueError):
        AppLifeCycle('INSTALLED').in_state('INVALID_STATE_STRING')
    with pytest.raises(ValueError):
        AppLifeCycle('APP_SPECIFIC0')
    with pytest.raises(ValueError):
        AppLifeCycle('APP_SPECIFIC16')


def test_SDLifeCycle():
    assert str(SDLifeCycle(0b00000011)) == 'INSTALLED'
    assert str(SDLifeCycle(0b00000111)) == 'SELECTABLE'
    assert str(SDLifeCycle(0b00001111)) == 'PERSONALIZED'
    assert SDLifeCycle(0b00000011).in_state('INSTALLED')
    assert SDLifeCycle(0b00000111).in_state('SELECTABLE')
    assert SDLifeCycle(0b00001111).in_state('PERSONALIZED')
    assert SDLifeCycle('INSTALLED').in_state('INSTALLED')
    assert SDLifeCycle('SELECTABLE').in_state('SELECTABLE')
    assert SDLifeCycle('PERSONALIZED').in_state('PERSONALIZED')
    for x in range(4):
        assert str(SDLifeCycle((x << 2) | 0b10000011)) == 'LOCKED'
        assert SDLifeCycle((x << 2) | 0b10000011).in_state('LOCKED')
    assert SDLifeCycle('LOCKED').in_state('LOCKED')

    with pytest.raises(ValueError):
        SDLifeCycle('INVALID_STATE_STRING')
    with pytest.raises(ValueError):
        SDLifeCycle(-1)
    with pytest.raises(ValueError):
        SDLifeCycle(256)
    with pytest.raises(ValueError):
        SDLifeCycle('INSTALLED').in_state('INVALID_STATE_STRING')


def test_CardLifeCycle():
    assert str(CardLifeCycle(0b00000001)) == 'OP_READY'
    assert str(CardLifeCycle(0b00000111)) == 'INITIALIZED'
    assert str(CardLifeCycle(0b00001111)) == 'SECURED'
    assert str(CardLifeCycle(0b01111111)) == 'CARD_LOCKED'
    assert str(CardLifeCycle(0b11111111)) == 'TERMINATED'

    assert str(CardLifeCycle('OP_READY')) == 'OP_READY'
    assert str(CardLifeCycle('INITIALIZED')) == 'INITIALIZED'
    assert str(CardLifeCycle('SECURED')) == 'SECURED'
    assert str(CardLifeCycle('CARD_LOCKED')) == 'CARD_LOCKED'
    assert str(CardLifeCycle('TERMINATED')) == 'TERMINATED'

    assert CardLifeCycle('OP_READY').in_state('OP_READY')
    assert CardLifeCycle('INITIALIZED').in_state('INITIALIZED')
    assert CardLifeCycle('SECURED').in_state('SECURED')
    assert CardLifeCycle('CARD_LOCKED').in_state('CARD_LOCKED')
    assert CardLifeCycle('TERMINATED').in_state('TERMINATED')

    with pytest.raises(ValueError):
        CardLifeCycle('INVALID_STATE_STRING')
    with pytest.raises(ValueError):
        CardLifeCycle(-1)
    with pytest.raises(ValueError):
        CardLifeCycle(256)
    with pytest.raises(ValueError):
        CardLifeCycle(0b00000011).in_state('INVALID_STATE_STRING')
