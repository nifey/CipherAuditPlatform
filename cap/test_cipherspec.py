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
    assert declarations[0].synthesize_c() == "uint8_t SBOX[3] = { 0x63, 0x7c, 0x77 };\n"
    assert declarations[1].synthesize_c() == "uint8_t KEY[3];\n"

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
    assert operations[0].synthesize_c() == "uint8_t MUL2 (uint8_t a) {\n\tuint8_t h, m, n, t;\n\th = (a>>7);\n\tt = (a<<1);\n\tn = (h*0x1b);\n\tm = (n^t);\n\treturn m;\n}\n"
    assert operations[1].synthesize_c() == "uint8_t MUL3 (uint8_t a, uint8_t b) {\n\tuint8_t c;\n\tc = (a*b);\n\treturn c;\n}\n"
    assert operations[2].synthesize_c() == "uint8_t MAX (uint8_t a, uint8_t b) {\n\tif (a > b) {\n\t\treturn a;\n\t} else {\n\t\treturn b;\n\t}\n}\n"
    assert operations[3].synthesize_c() == "uint8_t MAX3 (uint8_t a, uint8_t b, uint8_t c) {\n\tif (a > b) {\n\t\tif (a > c) {\n\t\t\treturn a;\n\t\t} else {\n\t\t\treturn c;\n\t\t}\n\t} else {\n\t\tif (b > c) {\n\t\t\treturn b;\n\t\t} else {\n\t\t\treturn c;\n\t\t}\n\t}\n}\n"
    assert operations[4].synthesize_c() == "uint8_t FACT (uint8_t n) {\n\tuint8_t n, sum;\n\tsum = 1;\n\twhile (n > 0) {\n\t\tsum = (sum*n);\n\t\tn = (n-1);\n\t}\n}\n"

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
    assert rounds[0].parts[2].get_input_values() == set(["F1[1]", "F1[2]"])
    assert rounds[1].name == "F3"
    assert rounds[1].linearity == "linear"
    assert rounds[1].type == "SWAP"
    assert len(rounds[1].parts) == 2
    assert rounds[1].parts[1].output_value == "F3[2]"
    assert rounds[1].parts[1].get_input_values() == set(["F2[2]"])

    # Synthesis tests
    assert rounds[0].synthesize_c() == "\t// Round F2\n\tF2[1] = SBOX[F1[1]];\n\tF2[2] = (SBOX[F1[2]]^F1[3]);\n\tF2[3] = (((F1[1]>>2)&1)^(F1[2]^0x1b));\n"
    assert rounds[1].synthesize_c() == "\t// Round F3\n\tF3[1] = F2[1];\n\tF3[2] = F2[2];\n"

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
    assert rounds[1].synthesize_c() == "\t// Round F5\n\tF17[0] = (F4[0]^KEY[23]);\n\tF5[1] = F21[1];\n"

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
        assert rounds[i].parts[16].synthesize_c() == "F" + str(round_num) + "[" + str(i) + "] = KEY[" + str(i+1) + "];"

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
                    ("F91",     "de 2b f2 fd 9b 74 aa cd f1 29 85 55 45 94 94 fd")]}
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
