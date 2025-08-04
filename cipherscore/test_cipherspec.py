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
                < h : { a : F_RS ( a , 7 ) } >
                < t : { a : F_LS ( a , 1 ) } >
                < n : { h : F_MUL ( h , '0x1b' ) } >
                < m : { ( n , t ) : F_XOR ( n , t ) } >
                ret m
            </func>

            <func> < F_MUL3 ( a , b ) >
                < c : { a, b : F_MUL ( a, b )} >
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
        < F2[1] : { ( F1[1] ) : F_LKUP( F1[1], SBOX ) }>
        < F2[2] : { ( F1[2], F1[3] ) : F_XOR ( F_LKUP( F1[2], SBOX ) , F1[3] ) }>
        < F2[3] : { ( F1[1]_[2], F1[2] ) : F_XOR ( F1[1]_[2], F_XOR( F1[2], '0x1b') ) }>
    />
    < F3 > < linear > < SWAP > <
        < F3[1] : { ( F2[1] ) } >
        < F3[2] : { ( F2[2] ) } >
    />
        """)
    assert len(rounds) == 2
    assert rounds[0].name == "F2"
    assert rounds[0].linearity == "nonlinear"
    assert rounds[0].type == "SUBBYTE"
    assert len(rounds[0].parts) == 3
    assert rounds[0].parts[2].output_value == "F2[3]"
    assert rounds[0].parts[2].input_values == ["F1[1]_[2]", "F1[2]"]
    assert rounds[1].name == "F3"
    assert rounds[1].linearity == "linear"
    assert rounds[1].type == "SWAP"
    assert len(rounds[1].parts) == 2
    assert rounds[1].parts[1].output_value == "F3[2]"
    assert rounds[1].parts[1].input_values == ["F2[2]"]

    # Synthesis tests
    assert rounds[0].synthesize_c() == "\t// Round F2\n\tF2[1] = SBOX[F1[1]];\n\tF2[2] = (SBOX[F1[2]]^F1[3]);\n\tF2[3] = (((F1[1]>>2)&1)^(F1[2]^0x1b));\n"
    assert rounds[1].synthesize_c() == "\t// Round F3\n\tF3[1] = F2[1];\n\tF3[2] = F2[2];\n"

def test_cipher_parser():
    # Parsing tests
    parser = cipher_parser()
    cipher = try_parsing(parser, """
<begin>
	<declaration>
		SBOX[256] { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0 b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75 09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2 cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08 ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16}
		KEY[16] { 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c }
	</declaration>

	<operations>
		 <func> < F_MUL2 ( a ) >
			< h : { a : F_RS ( a , 7 ) } >
			< t : { a : F_LS ( a , 1 ) } >
			< n : { h : F_MUL ( h , '0x1b' ) } >
			< m : { ( n , t ) : F_XOR ( n , t ) } >
			ret m
		</func>
		<func> < F_MUL3 ( a ) >
			< x : { a : F_MUL2 ( a ) } >
			< t : { ( x , a ) : F_XOR ( a , x ) } >
			ret t
		</func>
	</operations>

  	< F1 > < linear > < KEYXOR > <
  		< F1[1] : { ( F0[1] ) : F_XOR ( F0[1] , F_LKUP( 1  , KEY ) )  } >
  		< F1[2] : { ( F0[2] ) : F_XOR ( F0[2] , F_LKUP( 2  , KEY ) )  } >
  		< F1[3] : { ( F0[3] ) : F_XOR ( F0[3] , F_LKUP( 3  , KEY ) )  } >
  		< F1[4] : { ( F0[4] ) : F_XOR ( F0[4] , F_LKUP( 4  , KEY ) )  } >
  		< F1[5] : { ( F0[5] ) : F_XOR ( F0[5] , F_LKUP( 5  , KEY ) )  } >
  		< F1[6] : { ( F0[6] ) : F_XOR ( F0[6] , F_LKUP( 6  , KEY ) )  } >
  		< F1[7] : { ( F0[7] ) : F_XOR ( F0[7] , F_LKUP( 7  , KEY ) )  } >
  		< F1[8] : { ( F0[8] ) : F_XOR ( F0[8] , F_LKUP( 8  , KEY ) )  } >
  		< F1[9] : { ( F0[9] ) : F_XOR ( F0[9] , F_LKUP( 9  , KEY ) )  } >
  		< F1[10] : { ( F0[10] ) : F_XOR ( F0[10] , F_LKUP( 10  , KEY ) )  } >
  		< F1[11] : { ( F0[11] ) : F_XOR ( F0[11] , F_LKUP( 11  , KEY ) )  } >
  		< F1[12] : { ( F0[12] ) : F_XOR ( F0[12] , F_LKUP( 12  , KEY ) )  } >
  		< F1[13] : { ( F0[13] ) : F_XOR ( F0[13] , F_LKUP( 13  , KEY ) )  } >
  		< F1[14] : { ( F0[14] ) : F_XOR ( F0[14] , F_LKUP( 14  , KEY ) )  } >
  		< F1[15] : { ( F0[15] ) : F_XOR ( F0[15] , F_LKUP( 15  , KEY ) )  } >
  		< F1[16] : { ( F0[16] ) : F_XOR ( F0[16] , F_LKUP( 16  , KEY ) )  } >
  	/>
    < F2 > < nonlinear > < SUBBYTE > <
        < F2[1] : { ( F1[1] ) : F_LKUP( F1[1]  , SBOX ) } >
        < F2[2] : { ( F1[2] ) : F_LKUP( F1[2]  , SBOX ) } >
        < F2[3] : { ( F1[3] ) : F_LKUP(  F1[3]  , SBOX ) } >
        < F2[4] : { ( F1[4] ) : F_LKUP( F1[4]  , SBOX ) } >
        < F2[5] : { ( F1[5] ) : F_LKUP( F1[5]  , SBOX ) } >
        < F2[6] : { ( F1[6] ) : F_LKUP( F1[6]  , SBOX ) } >
        < F2[7] : { ( F1[7] ) : F_LKUP( F1[7]  , SBOX ) } >
        < F2[8] : { ( F1[8] ) : F_LKUP( F1[8]  , SBOX ) } >
        < F2[9] : { ( F1[9] ) : F_LKUP( F1[9]  , SBOX ) } >
        < F2[10] : { ( F1[10] ) : F_LKUP( F1[10]  , SBOX ) } >
        < F2[11] : { ( F1[11] ) : F_LKUP( F1[11]  , SBOX ) } >
        < F2[12] : { ( F1[12] ) : F_LKUP( F1[12]  , SBOX ) } >
        < F2[13] : { ( F1[13] ) : F_LKUP( F1[13]  , SBOX ) } >
        < F2[14] : { ( F1[14] ) : F_LKUP( F1[14]  , SBOX ) } >
        < F2[15] : { ( F1[15] ) : F_LKUP( F1[15]  , SBOX ) } >
        < F2[16] : { ( F1[16] ) : F_LKUP( F1[16]  , SBOX ) } >
    />
    < F3 > < linear > < SWAP > <
  		< F3[1] : { ( F2[1] ) } >
  		< F3[2] : { ( F2[6] ) } >
  		< F3[3] : { ( F2[11] ) } >
  		< F3[4] : { ( F2[16] ) } >
  		< F3[5] : { ( F2[5] ) } >
  		< F3[6] : { ( F2[10] ) } >
  		< F3[7] : { ( F2[15] ) } >
  		< F3[8] : { ( F2[4] ) } >
  		< F3[9] : { ( F2[9] ) } >
  		< F3[10] : { ( F2[14] ) } >
  		< F3[11] : { ( F2[3] ) } >
  		< F3[12] : { ( F2[8] ) } >
  		< F3[13] : { ( F2[13] ) } >
  		< F3[14] : { ( F2[2] ) } >
  		< F3[15] : { ( F2[7] ) } >
  		< F3[16] : { ( F2[12] ) } >
  	/>
  < F4 > < linear > < MDS > <
		< F4[1] : { ( F3[1] , F3[2] , F3[3] , F3[4] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[1] ) , F_MUL3 ( F3[2] ) ) , F_XOR ( F3[3]  , F3[4] ) )  } >
		< F4[2] : { ( F3[1] , F3[2] , F3[3] , F3[4] )
            :  F_XOR ( F_XOR ( F_MUL2 ( F3[2] ) , F_MUL3 ( F3[3] ) ) , F_XOR ( F3[1]  , F3[4] ) ) } >
		< F4[3] : { ( F3[1] , F3[2] , F3[3] , F3[4] )
            :  F_XOR ( F_XOR ( F_MUL2 ( F3[3] ) , F_MUL3 ( F3[4] ) ) , F_XOR ( F3[1]  , F3[2] ) )  } >
		< F4[4] : { ( F3[1] , F3[2] , F3[3] , F3[4] )
            :  F_XOR ( F_XOR ( F_MUL2 ( F3[4] ) , F_MUL3 ( F3[1] ) ) , F_XOR ( F3[2]  , F3[3] ) ) } >
		< F4[5] : { ( F3[5] , F3[6] , F3[7] , F3[8] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[5] ) , F_MUL3 ( F3[6] ) ) , F_XOR ( F3[7]  , F3[8] )  ) } >
		< F4[6] : { ( F3[5] , F3[6] , F3[7] , F3[8] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[6] ) , F_MUL3 ( F3[7] ) ) , F_XOR ( F3[5]  , F3[8] )  ) } >
		< F4[7] : { ( F3[5] , F3[6] , F3[7] , F3[8] )
            :  F_XOR ( F_XOR ( F_MUL2 ( F3[7] ) , F_MUL3 ( F3[8] ) ) , F_XOR ( F3[5]  , F3[6] ) )  } >
		< F4[8] : { ( F3[5] , F3[6] , F3[7] , F3[8] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[8] ) , F_MUL3 ( F3[5] ) ) , F_XOR ( F3[6]  , F3[7] ) )  } >
		< F4[9] : { ( F3[9] , F3[10] , F3[11] , F3[12] )
            :  F_XOR ( F_XOR ( F_MUL2 ( F3[9] ) , F_MUL3 ( F3[10] ) ) , F_XOR ( F3[11]  , F3[12] ) ) } >
		< F4[10] : { ( F3[9] , F3[10] , F3[11] , F3[12] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[10] ) , F_MUL3 ( F3[11] ) ) , F_XOR ( F3[9]  , F3[12] ) ) } >
		< F4[11] : { ( F3[9] , F3[10] , F3[11] , F3[12] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[11] ) , F_MUL3 ( F3[12] ) ) , F_XOR ( F3[9]  , F3[10] ) )  } >
		< F4[12] : { ( F3[9] , F3[10] , F3[11] , F3[12] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[12] ) , F_MUL3 ( F3[9] ) ) , F_XOR ( F3[10]  , F3[11] ) ) } >
		< F4[13] : { ( F3[13] , F3[14] , F3[15] , F3[16] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[13] ) , F_MUL3 ( F3[14] ) ) , F_XOR ( F3[15]  , F3[16] ) ) } >
		< F4[14] : { ( F3[13] , F3[14] , F3[15] , F3[16] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[14] ) , F_MUL3 ( F3[15] ) ) , F_XOR ( F3[13]  , F3[16] ) ) } >
		< F4[15] : { ( F3[13] , F3[14] , F3[15] , F3[16] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[15] ) , F_MUL3 ( F3[16] ) ) , F_XOR ( F3[13]  , F3[14] ) ) } >
		< F4[16] : { ( F3[13] , F3[14] , F3[15] , F3[16] )
            : F_XOR ( F_XOR ( F_MUL2 ( F3[16] ) , F_MUL3 ( F3[13] ) ) , F_XOR ( F3[14]  , F3[15] ) ) } >
	/>
  <end>""")
    cipher = cipher[0]
    assert len(cipher.declarations) == 2
    assert len(cipher.operations) == 2
    assert len(cipher.rounds) == 4

    # Synthesis tests
    assert cipher.synthesize_c() == "#include<stdio.h>\n#include<stdlib.h>\n#include<math.h>\n#include<stdint.h>\n\nuint8_t SBOX[256] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };\n\nuint8_t KEY[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };\n\nuint8_t MUL2 (uint8_t a) {\n\tuint8_t h = (a>>7);\n\tuint8_t t = (a<<1);\n\tuint8_t n = (h*0x1b);\n\tuint8_t m = (n^t);\n\treturn m;\n}\n\nuint8_t MUL3 (uint8_t a) {\n\tuint8_t x = MUL2(a);\n\tuint8_t t = (a^x);\n\treturn t;\n}\n\nvoid roundFunction(uint8_t F0[16]) {\n\tuint8_t F1[64], F2[64], F3[64], F4[64];\n\t// Round F1\n\tF1[1] = (F0[1]^KEY[1]);\n\tF1[2] = (F0[2]^KEY[2]);\n\tF1[3] = (F0[3]^KEY[3]);\n\tF1[4] = (F0[4]^KEY[4]);\n\tF1[5] = (F0[5]^KEY[5]);\n\tF1[6] = (F0[6]^KEY[6]);\n\tF1[7] = (F0[7]^KEY[7]);\n\tF1[8] = (F0[8]^KEY[8]);\n\tF1[9] = (F0[9]^KEY[9]);\n\tF1[10] = (F0[10]^KEY[10]);\n\tF1[11] = (F0[11]^KEY[11]);\n\tF1[12] = (F0[12]^KEY[12]);\n\tF1[13] = (F0[13]^KEY[13]);\n\tF1[14] = (F0[14]^KEY[14]);\n\tF1[15] = (F0[15]^KEY[15]);\n\tF1[16] = (F0[16]^KEY[16]);\n\n\t// Round F2\n\tF2[1] = SBOX[F1[1]];\n\tF2[2] = SBOX[F1[2]];\n\tF2[3] = SBOX[F1[3]];\n\tF2[4] = SBOX[F1[4]];\n\tF2[5] = SBOX[F1[5]];\n\tF2[6] = SBOX[F1[6]];\n\tF2[7] = SBOX[F1[7]];\n\tF2[8] = SBOX[F1[8]];\n\tF2[9] = SBOX[F1[9]];\n\tF2[10] = SBOX[F1[10]];\n\tF2[11] = SBOX[F1[11]];\n\tF2[12] = SBOX[F1[12]];\n\tF2[13] = SBOX[F1[13]];\n\tF2[14] = SBOX[F1[14]];\n\tF2[15] = SBOX[F1[15]];\n\tF2[16] = SBOX[F1[16]];\n\n\t// Round F3\n\tF3[1] = F2[1];\n\tF3[2] = F2[6];\n\tF3[3] = F2[11];\n\tF3[4] = F2[16];\n\tF3[5] = F2[5];\n\tF3[6] = F2[10];\n\tF3[7] = F2[15];\n\tF3[8] = F2[4];\n\tF3[9] = F2[9];\n\tF3[10] = F2[14];\n\tF3[11] = F2[3];\n\tF3[12] = F2[8];\n\tF3[13] = F2[13];\n\tF3[14] = F2[2];\n\tF3[15] = F2[7];\n\tF3[16] = F2[12];\n\n\t// Round F4\n\tF4[1] = ((MUL2(F3[1])^MUL3(F3[2]))^(F3[3]^F3[4]));\n\tF4[2] = ((MUL2(F3[2])^MUL3(F3[3]))^(F3[1]^F3[4]));\n\tF4[3] = ((MUL2(F3[3])^MUL3(F3[4]))^(F3[1]^F3[2]));\n\tF4[4] = ((MUL2(F3[4])^MUL3(F3[1]))^(F3[2]^F3[3]));\n\tF4[5] = ((MUL2(F3[5])^MUL3(F3[6]))^(F3[7]^F3[8]));\n\tF4[6] = ((MUL2(F3[6])^MUL3(F3[7]))^(F3[5]^F3[8]));\n\tF4[7] = ((MUL2(F3[7])^MUL3(F3[8]))^(F3[5]^F3[6]));\n\tF4[8] = ((MUL2(F3[8])^MUL3(F3[5]))^(F3[6]^F3[7]));\n\tF4[9] = ((MUL2(F3[9])^MUL3(F3[10]))^(F3[11]^F3[12]));\n\tF4[10] = ((MUL2(F3[10])^MUL3(F3[11]))^(F3[9]^F3[12]));\n\tF4[11] = ((MUL2(F3[11])^MUL3(F3[12]))^(F3[9]^F3[10]));\n\tF4[12] = ((MUL2(F3[12])^MUL3(F3[9]))^(F3[10]^F3[11]));\n\tF4[13] = ((MUL2(F3[13])^MUL3(F3[14]))^(F3[15]^F3[16]));\n\tF4[14] = ((MUL2(F3[14])^MUL3(F3[15]))^(F3[13]^F3[16]));\n\tF4[15] = ((MUL2(F3[15])^MUL3(F3[16]))^(F3[13]^F3[14]));\n\tF4[16] = ((MUL2(F3[16])^MUL3(F3[13]))^(F3[14]^F3[15]));\n\n}\n\nint main() {\n\tuint8_t pt[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a , 0x30 , 0x8d ,0x31, 0x31 , 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};\n\troundFunction(pt);\n}"
