import pytest
from omfgp.gp_types import *


def test_deserialize():
    assert (Privileges.deserialize(bytes.fromhex("C24210")) ==
            ['security_domain', 'dap_verification', 'cvm_management',
            'authorized_management', 'final_application',
            'contactless_self_activation'])
    # TODO exhaustive test
    pass


def test_serialize():
    assert (Privileges(['security_domain', 'dap_verification', 'cvm_management',
            'authorized_management', 'final_application',
            'contactless_self_activation']).serialize() ==
            bytes.fromhex("C24210"))
    # TODO exhaustive test
    pass