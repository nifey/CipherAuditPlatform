#################################################################################################
# This file contains unit tests for BCSL parsing and synthesis
#################################################################################################

from pyparsing import ParserElement, ParseException
from .cipherspec import declarations_parser, operations_parser, rounds_parser, cipher_parser
from .cipherspec import Declaration, Operation, Round

def try_parsing(parser: ParserElement, string : str):
    """Try parsing the string with the given parser. If exception occurs print error and fail"""
    try:
        return parser.parseString(string)
    except ParseException as e:
        print(e)
        assert False

def test_declarations():
    # Parsing tests
    parser = declarations_parser()
    try_parsing(parser, """<declaration></declaration>""")
    try_parsing(parser, """<declaration> SBOX[123] </declaration>""")
    try_parsing(parser, """<declaration> SBOX[123] KEY[16] </declaration>""")
    try_parsing(parser, """<declaration> SBOX[3] { 63 7c 77 } KEY[16] </declaration>""")
    try_parsing(parser, """<declaration> SBOX[123] KEY[3] { ab cd ef } </declaration>""")
    declarations = try_parsing(parser, \
            """<declaration> SBOX[3] { 63 7c 77 } KEY[3] </declaration>""")
    assert len(declarations) == 2
    assert declarations[0].name == "SBOX"
    assert declarations[0].len == 3
    assert declarations[0].data == ["63", "7c", "77"]
    assert declarations[1].name == "KEY"
    assert declarations[1].len == 3
    assert declarations[1].data == []

    # Synthesis tests
    assert declarations[0].synthesize_c() == "uint8_t SBOX[3] = { 0x63, 0x7c, 0x77 };\n"
    assert declarations[1].synthesize_c() == "uint8_t KEY[3];\n"

def test_operations():
    # Parsing tests
    parser = operations_parser()
    try_parsing(parser, """<operations></operations>""")
    operations = try_parsing(parser, """<operations>
            <func> < F_MUL2 ( a ) >
                < h : F_RS ( a , 7 ) >
                < t : F_LS ( a , 1 ) >
                < n : F_MUL ( h , '0x1b' ) >
                < m : F_XOR ( n , t ) >
                ret m
            </func>

            <func> < F_MUL3 ( a , b ) >
                < c : F_MUL ( a, b ) >
                ret c
            </func>
        </operations>""")
    assert len(operations) == 2
    assert operations[0].name == "F_MUL2"
    assert operations[0].arguments == ["a"]
    assert len(operations[0].statements) == 5
    assert operations[1].name == "F_MUL3"
    assert operations[1].arguments == ["a", "b"]
    assert len(operations[1].statements) == 2

    # Synthesis tests
    assert operations[0].synthesize_c() == "uint8_t MUL2 (uint8_t a) {\n\tuint8_t h = (a>>7);\n\tuint8_t t = (a<<1);\n\tuint8_t n = (h*0x1b);\n\tuint8_t m = (n^t);\n\treturn m;\n}\n"
    assert operations[1].synthesize_c() == "uint8_t MUL3 (uint8_t a, uint8_t b) {\n\tuint8_t c = (a*b);\n\treturn c;\n}\n"

def test_rounds_parser():
    # Parsing tests
    parser = rounds_parser()
    rounds = try_parsing(parser, """
    < F2 > < nonlinear > < SUBBYTE > < 
        < F2[1] : F_LKUP( F1[1], SBOX ) >
        < F2[2] : F_XOR ( F_LKUP( F1[2], SBOX ) , F1[3] ) >
        < F2[3] : F_XOR ( F1[1]_[2], F_XOR( F1[2], '0x1b') ) >
    />
    < F3 > < linear > < SWAP > <
        < F3[1] : F2[1] >
        < F3[2] : F2[2] >
    />
        """)
    assert len(rounds) == 2
    assert rounds[0].name == "F2"
    assert rounds[0].linearity == "nonlinear"
    assert rounds[0].type == "SUBBYTE"
    assert len(rounds[0].parts) == 3
    assert rounds[0].parts[2].output_value == "F2[3]"
    assert rounds[1].name == "F3"
    assert rounds[1].linearity == "linear"
    assert rounds[1].type == "SWAP"
    assert len(rounds[1].parts) == 2
    assert rounds[1].parts[1].output_value == "F3[2]"

    # Synthesis tests
    assert rounds[0].synthesize_c() == "\t// Round F2\n\tF2[1] = SBOX[F1[1]];\n\tF2[2] = (SBOX[F1[2]]^F1[3]);\n\tF2[3] = (((F1[1]>>2)&1)^(F1[2]^0x1b));\n"
    assert rounds[1].synthesize_c() == "\t// Round F3\n\tF3[1] = F2[1];\n\tF3[2] = F2[2];\n"
