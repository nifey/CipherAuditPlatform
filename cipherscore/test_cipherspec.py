#################################################################################################
# This file contains unit tests for BCSL parsing
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

def test_declarations_parser():
    parser = declarations_parser()
    try_parsing(parser, """<declaration></declaration>""")
    try_parsing(parser, """<declaration> SBOX[123] </declaration>""")
    try_parsing(parser, """<declaration> SBOX[123] KEY[16] </declaration>""")
    try_parsing(parser, """<declaration> SBOX[3] { 63 7c 77 } KEY[16] </declaration>""")
    try_parsing(parser, """<declaration> SBOX[123] KEY[3] { ab cd ef } </declaration>""")
    declarations = try_parsing(parser, \
            """<declaration> SBOX[3] { 63 7c 77 } KEY[3] { ab cd ef } </declaration>""")
    assert len(declarations) == 2
    assert declarations[0].name == "SBOX"
    assert declarations[0].len == 3
    assert declarations[0].data == ["63", "7c", "77"]
    assert declarations[1].name == "KEY"
    assert declarations[1].len == 3
    assert declarations[1].data == ["ab", "cd", "ef"]

def test_operations_parser():
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

def test_rounds_parser():
    parser = rounds_parser()
    rounds = try_parsing(parser, """
    < F2 > < nonlinear > < SUBBYTE > < 
        < F2[1] : { ( F1[1] ) : F_LKUP( F1[1], SBOX ) }>
        < F2[2] : { ( F1[2], F1[3] ) : F_XOR ( F_LKUP( F1[2], SBOX ) , F1[3] ) }>
        < F2[3] : { ( F1[1], F1[2], F1[3] ) : F_XOR ( F1[1], F_XOR( F1[2], F1[3] ) ) }>
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
    assert rounds[0].parts[2].input_values == ["F1[1]", "F1[2]", "F1[3]"]
    assert rounds[1].name == "F3"
    assert rounds[1].linearity == "linear"
    assert rounds[1].type == "SWAP"
    assert len(rounds[1].parts) == 2
    assert rounds[1].parts[1].output_value == "F3[2]"
    assert rounds[1].parts[1].input_values == ["F2[2]"]

def test_cipher_parser():
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
    assert len(cipher) == 8 # 2 declarations, 2 operations, 4 rounds
    assert isinstance(cipher[0], Declaration)
    assert isinstance(cipher[2], Operation)
    assert isinstance(cipher[4], Round)
