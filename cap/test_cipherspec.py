#################################################################################################
# This file contains unit tests for CSL parsing and synthesis
#################################################################################################

import subprocess
from pyparsing import ParserElement, ParseException
from .cipherspec import declarations_parser, operations_parser, rounds_parser, cipher_parser
from .cipherspec import Declaration, Operation, Round, GenericRound

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
    assert declarations[0].synthesize_c() == "uint64_t SBOX[3] = { 0x63, 0x7c, 0x77 };\n"
    assert declarations[1].synthesize_c() == "uint64_t KEY[3];\n"

def test_operations():
    # Parsing tests
    parser = operations_parser()
    try_parsing(parser, """<operation></operation>""")
    operations = try_parsing(parser, """<operation>
            <func> < F_MUL2 ( a ) >
                < h : F_RS ( a , 7 ) >
                < t : F_LS ( a , 1 ) >
                < n : F_MUL ( h , '0x1b' ) >
                < m : F_XOR ( n , t ) >
                < ret m >
            </func>

            <func> < F_MUL3 ( a , b ) >
                < c : F_MUL ( a, b ) >
                < ret c >
            </func>

            <func> < F_MAX ( a, b ) >
                <if a GT b>
                    < ret a >
                <else>
                    < ret b >
                </if>
            </func>

            <func> < F_MAX3 ( a, b, c ) >
                <if a GT b>
                    <if a GT c>
                        < ret a >
                    <else>
                        < ret c >
                    </if>
                <else>
                    <if b GT c>
                        < ret b >
                    <else>
                        < ret c >
                    </if>
                </if>
            </func>
 
            <func> < F_FACT ( n ) >
                <sum : 1>
                <while n GT 0 >
                    < sum : F_MUL(sum,n) >
                    < n : F_SUB(n, 1) >
                </while>
            </func>

        </operation>""")
    assert len(operations) == 5
    assert operations[0].name == "F_MUL2"
    assert operations[0].arguments == ["a"]
    assert len(operations[0].statements) == 5
    assert operations[1].name == "F_MUL3"
    assert operations[1].arguments == ["a", "b"]
    assert len(operations[1].statements) == 2

    # Synthesis tests
    assert operations[0].synthesize_c() == "uint64_t MUL2 (uint64_t a) {\n\tuint64_t h, m, n, t;\n\th = (a>>7);\n\tt = (a<<1);\n\tn = (h*0x1b);\n\tm = (n^t);\n\treturn m;\n}\n"
    assert operations[1].synthesize_c() == "uint64_t MUL3 (uint64_t a, uint64_t b) {\n\tuint64_t c;\n\tc = (a*b);\n\treturn c;\n}\n"
    assert operations[2].synthesize_c() == "uint64_t MAX (uint64_t a, uint64_t b) {\n\tif (a > b) {\n\t\treturn a;\n\t} else {\n\t\treturn b;\n\t}\n}\n"
    assert operations[3].synthesize_c() == "uint64_t MAX3 (uint64_t a, uint64_t b, uint64_t c) {\n\tif (a > b) {\n\t\tif (a > c) {\n\t\t\treturn a;\n\t\t} else {\n\t\t\treturn c;\n\t\t}\n\t} else {\n\t\tif (b > c) {\n\t\t\treturn b;\n\t\t} else {\n\t\t\treturn c;\n\t\t}\n\t}\n}\n"
    assert operations[4].synthesize_c() == "uint64_t FACT (uint64_t n) {\n\tuint64_t n, sum;\n\tsum = 1;\n\twhile (n > 0) {\n\t\tsum = (sum*n);\n\t\tn = (n-1);\n\t}\n}\n"

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
        < F3[3]_[0] : F2[3]_[0] >
        < F3[3]_[4:5] : F2[3]_[2:3] >
        < F3[3]_[3:2] : F2[3]_[5:4] >
        < F3[4]_[7:4] : F_ROL(F2[3]_[3:0], 3) >
        < F3[4]_[3:0] : F_ROR(F2[3]_[5:2], 3) >
    />
        """)
    assert len(rounds) == 2
    assert rounds[0].name == "F2"
    assert rounds[0].linearity == "nonlinear"
    assert rounds[0].type == "SUBBYTE"
    assert len(rounds[0].parts) == 3
    assert rounds[0].parts[2].output_value == "F2[3]"
    assert rounds[0].parts[2].get_input_values() == set(["F1[1]", "F1[2]"])
    assert rounds[1].name == "F3"
    assert rounds[1].linearity == "linear"
    assert rounds[1].type == "SWAP"
    assert len(rounds[1].parts) == 7
    assert rounds[1].parts[1].output_value == "F3[2]"
    assert rounds[1].parts[1].get_input_values() == set(["F2[2]"])

    # Synthesis tests
    assert rounds[0].synthesize_c() == "\t// Round F2\n\tF[2][1] = SBOX[F[1][1]];\n\tF[2][2] = (SBOX[F[1][2]]^F[1][3]);\n\tF[2][3] = (BIT_SELECT(F[1][1],2)^(F[1][2]^0x1b));\n"
    assert rounds[1].synthesize_c() == "\t// Round F3\n\tF[3][1] = F[2][1];\n" + \
            "\tF[3][2] = F[2][2];\n" + \
            "\tF[3][3] = (F[3][3] & (~BIT(0))) | ((BIT_SELECT(F[2][3],0)<<0) & BIT(0));\n" + \
            "\tF[3][3] = (F[3][3] & (~BITRANGE_BITMASK(5,4))) |" + \
                " ((BITRANGE_SELECT(F[2][3],3,2)<<4) & BITRANGE_BITMASK(5,4));\n" + \
            "\tF[3][3] = (F[3][3] & (~BITRANGE_BITMASK(3,2))) |" + \
                " ((BITRANGE_SELECT(F[2][3],5,4)<<2) & BITRANGE_BITMASK(3,2));\n" + \
            "\tF[3][4] = (F[3][4] & (~BITRANGE_BITMASK(7,4))) |" + \
                " (((((BITRANGE_SELECT(F[2][3],3,0)&BITMASK(0))<<3)|((BITRANGE_SELECT(F[2][3],3,0)>>1)&BITMASK(2)))<<4) & BITRANGE_BITMASK(7,4));\n" + \
            "\tF[3][4] = (F[3][4] & (~BITRANGE_BITMASK(3,0))) |" + \
                " (((((BITRANGE_SELECT(F[2][3],5,2)<<1)&BITMASK(3))|(BITRANGE_SELECT(F[2][3],5,2)>>3))<<0) & BITRANGE_BITMASK(3,0));\n"

def test_generic_rounds_parser():
    # Parsing tests
    parser = rounds_parser()
    rounds = try_parsing(parser, """
    < for i in [1:41:4] >
  	< F{i} > < linear > < KEYXOR > <
        < F{4+3*i-2}[0]  : F_XOR( F{i-1}[0]  , F_LKUP( {3+4*i}  , KEY ) ) >
        < F{i}[1]  : F{i*4+1}[1] >
  	/>
        """)

    assert isinstance(rounds[0], GenericRound)
    rounds = rounds[0].generate_rounds()
    assert len(rounds) == 11
    for i, round_num in enumerate(range(1, 42, 4)):
        assert rounds[i].name == "F" + str(round_num)
        assert rounds[i].linearity == "linear"
        assert rounds[i].type == "KEYXOR"
        assert len(rounds[i].parts) == 2
        assert rounds[i].parts[0].output_value == "F" + str(4+3*round_num-2) + "[0]"
        assert rounds[i].parts[1].output_value == "F" + str(round_num) + "[1]"
    assert rounds[1].synthesize_c() == "\t// Round F5\n\tF[17][0] = (F[4][0]^KEY[23]);\n\tF[5][1] = F[21][1];\n"

    rounds = try_parsing(parser, """
    < for i in [0:9] >
    < F{i*4+3} > < linear > < SWAP > <
        < for j in [0:15] >
        < F{i*4+3}[{i+j}] : F2[{j+1}] >
        < F{i*4+3}[{i}] : F_LKUP( {i+1}, KEY ) >
    />
        """)

    assert isinstance(rounds[0], GenericRound)
    rounds = rounds[0].generate_rounds()
    assert len(rounds) == 10
    for i, round_num in enumerate(range(3, 40, 4)):
        assert rounds[i].name == "F" + str(round_num)
        assert rounds[i].linearity == "linear"
        assert rounds[i].type == "SWAP"
        assert len(rounds[i].parts) == 17
        for j in range(16):
            assert rounds[i].parts[j].output_value == "F" + str(round_num) + "[" + str(i+j) + "]"
        assert rounds[i].parts[16].synthesize_c() == "F[" + str(round_num) + "][" + str(i) + "] = KEY[" + str(i+1) + "];"

def synthesize_and_get_output(cipher):
    with open("test.c", "w+") as synthesis_file:
        synthesis_file.write(cipher.synthesize_c())
    process = subprocess.run(["gcc", "test.c", "-o", "test"])
    if process.returncode != 0:
        print("Compilation of generated code failed with error code " + str(process.returncode))
        assert False
    process = subprocess.run(["./test"], capture_output=True)
    if process.returncode != 0:
        print("Program exited with error code " + str(process.returncode))
        assert False
    output = process.stdout.decode("utf-8")
    subprocess.run(["rm", "test.c", "test"])
    return output

cipher_testcases = [
        {"file" : "specifications/AES_128.csl",     "declarations" : 3,     "operations" : 2,   "rounds" : 40,
         "tests" : [("F4",      "5c ad 56 37 ee db 3c 19 b9 79 82 af 1f e0 06 e4"),
                    ("F40",     "50 fe 67 cc 99 6d 32 b6 da 09 37 e9 9b af ec 60")]},
        {"file" : "specifications/CLEFIA_128.csl",  "declarations" : 5,     "operations" : 5,   "rounds" : 91,
         "tests" : [("F1",      "00 01 02 03 fb eb db cb 08 09 0a 0b b7 a7 97 87"),
                    ("F2",      "f3 e7 cc fa 85 fe 54 33"),
                    ("F3",      "29 02 46 e1 77 7d e8 e8"),
                    ("F4",      "54 7a 31 93 ab f1 20 70"),
                    ("F6",      "af 91 ea 58 08 09 0a 0b 1c 56 b7 f7 00 01 02 03"),
                    ("F91",     "de 2b f2 fd 9b 74 aa cd f1 29 85 55 45 94 94 fd")]},
        {"file" : "specifications/PRESENT_80.csl",  "declarations" : 3,     "operations" : 0,   "rounds" : 94,
         "tests" : [("F1",      "00 01 02 03 04 05 06 07"),
                    ("F2",      "cc c5 c6 cb c9 c0 ca cd"),
                    ("F3",      "eb ef fe ab 05 04 11 41"),
                    ("F94",     "95 bc 3e b3 1a b5 51 0d")]},
        {"file" : "specifications/SPECK_128.csl",  "declarations" : 2,     "operations" : 0,   "rounds" : 160,
         "tests" : [("F1",      "00 01"),
                    ("F2",      "01 01"),
                    ("F3",      "706050403020101 01"),
                    ("F4",      "706050403020101 08"),
                    ("F5",      "706050403020101 706050403020109"),
                    ("F160",    "f1182e3caaedf81d c12c80875bbe3fe")]},
        {"file" : "specifications/CHACHA20.csl",  "declarations" : 4,     "operations" : 0,   "rounds" : 242,
         "tests" : [("F1",      "61707865 3320646e 79622d32 6b206574 3020100 7060504 b0a0908 f0e0d0c 13121110 17161514 1b1a1918 1f1e1d1c 01 9000000 4a000000 00"),
                    ("F2",      "64727965 3a266972 846c363a 7a2e7280 3020100 7060504 b0a0908 f0e0d0c 13121110 17161514 1b1a1918 1f1e1d1c 01 9000000 4a000000 00"),
                    ("F3",      "64727965 3a266972 846c363a 7a2e7280 3020100 7060504 b0a0908 f0e0d0c 13121110 17161514 1b1a1918 1f1e1d1c 64727964 33266972 ce6c363a 7a2e7280"),
                    ("F24",     "cd52e917 85ab03b4 b3457395 f96de7dd 45896f9a f4b85c30 c392bd68 3462d900 7bf7d740 7eddd644 f1a1bdf5 761246ca 6b0d58a3 6798471a d737f167 f173888d"),
                    ("F242",    "e4e7f110 15593bd1 1fdd0f50 c47120a3 c7f4d1c7 368c033 9aaa2204 4e6cd4c3 466482d2 9aa9f07 5d7c214 a2028bd9 d19c12b5 b94e16de e883d0cb 4e3c50a2")]},
        {"file" : "specifications/ASCON128.csl",  "declarations" : 6,     "operations" : 0,   "rounds" : 97,
         "tests" : [("F1",      "80400c0600000000 1020304050607 8090a0b0c0d0e0f 1020304050607 8090a0b0c0d0e0f "),
                    ("F3",      "8849060f0c0d0eff 80410e05040506f7 ffffffffffffff0f 80400406000000f0 808080a08080808 "),
                    ("F97",     "aa10856137c5a410 c4484049c5056bc1 2bfaa1972589c50d 69715fb4556decd1 d4d4834ea4923c12 ")]},
        ]

def test_cipher_parser():
    for testcase in cipher_testcases:
        with open(testcase["file"], "r") as specfile:
            specification = specfile.read()

        # Parsing tests
        parser = cipher_parser()
        cipher = try_parsing(parser, specification)
        cipher = cipher[0]
        assert len(cipher.declarations) == testcase["declarations"]
        assert len(cipher.operations)   == testcase["operations"]
        assert len(cipher.rounds)       == testcase["rounds"]
        test_checked = set()
        output = synthesize_and_get_output(cipher)
        for line in output.split("\n"):
            for test_round, test_data in testcase["tests"]:
                if line.startswith(test_round + "\t"):
                    test_checked.add(test_round)
                    if test_data not in line:
                        print("Test failed for " + testcase["file"])
                        print(test_round)
                        print(test_data)
                        print(output)
                        assert False
        for test_round, test_data in testcase["tests"]:
            if test_round not in test_checked:
                print("Test failed for " + testcase["file"])
                print(test_round)
                print(test_data)
                print(output)
                assert False
