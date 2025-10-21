#################################################################################################
# This file contains unit tests for fault characterization
#################################################################################################
from pyparsing import ParserElement
from .cipherspec import cipher_parser
from .fault_characterization import get_fault_exploitability

def test_aes_fault_characterization():
    with open("specifications/AES_128.csl", "r") as specfile:
        specification = specfile.read()
    cipher = cipher_parser().parseString(specification)[0]

    assert get_fault_exploitability(cipher, 27, 0) == (0, 0)
    assert get_fault_exploitability(cipher, 28, 0) == (128, 2**8)
    assert get_fault_exploitability(cipher, 31, 0) == (128, 2**8)
    assert get_fault_exploitability(cipher, 32, 0) == (32, 2**8)
    assert get_fault_exploitability(cipher, 35, 0) == (32, 2**8)
    assert get_fault_exploitability(cipher, 36, 0) == (0, 0)
