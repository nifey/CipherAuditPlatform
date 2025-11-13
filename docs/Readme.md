# Cipher Audit Platform Documentation

### Cipher Specification Language (CSL) by example

In this section, we will understand how to write a block cipher specification in Cipher Specification Language (CSL), by going through the AES-128 specification written in CSL.

Every CSL specification consists of three parts written in between `<begin>` and `<end>` tags:
1. **Declarations**
    - Declarations represents the hard-coded data tables that are used in the Cipher. This includes SBox values, T-Tables, and Keys.
    - The declarations are defined between `<declaration>` and `</declaration>` tags.
    - Each declaration consists of a name, it's length, followed by the individual elements as hex values.
    - The following is the declaration showing the SBox and Key of AES. Note that currently CSL doesn't support specifying Key expansion and so we have to hard code the expanded key as a declaration. This will be fixed in later versions of the tool.
    ```
    <declaration>
        SBOX[256] { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0 b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75 09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2 cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08 ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16}
        KEY[16] { 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c}
        EXPANDED_KEY[176] { 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c a0 fa fe 17 88 54 2c b1 23 a3 39 39 2a 6c 76 05 f2 c2 95 f2 7a 96 b9 43 59 35 80 7a 73 59 f6 7f 3d 80 47 7d 47 16 fe 3e 1e 23 7e 44 6d 7a 88 3b ef 44 a5 41 a8 52 5b 7f b6 71 25 3b db 0b ad 00 d4 d1 c6 f8 7c 83 9d 87 ca f2 b8 bc 11 f9 15 bc 6d 88 a3 7a 11 0b 3e fd db f9 86 41 ca 00 93 fd 4e 54 f7 0e 5f 5f c9 f3 84 a6 4f b2 4e a6 dc 4f ea d2 73 21 b5 8d ba d2 31 2b f5 60 7f 8d 29 2f ac 77 66 f3 19 fa dc 21 28 d1 29 41 57 5c 00 6e d0 14 f9 a8 c9 ee 25 89 e1 3f 0c c8 b6 63 0c a6}
    </declaration>
    ```
2. **Operations**
    - Operations represents the user defined operations used in the rounds of the cipher. This can be used to define custom operations apart from the in-built operations that CSL provides.
    - The operations are defined between `<operation>` and `</operation>` tags. The individual operations are defined between `<func>` and `</func>` tags. The tag following the `<func>` tag, specifies the name of the operation and the arguments used.
    - The body of the operation consists of a sequence of operations that operates on the arguments or constants.
    - For example `< h : F_RS   ( a , 7 ) >` defines a statement where the variable h will be assigned the value `a >> 7`. `F_RS` is an in-built function that performs right shift operation. 
    - List of in-built functions: `F_RS`, `F_LS`, `F_ADD`, `F_SUB`, `F_MUL`, `F_XOR`, `F_AND`, `F_LKUP`, used to perform Right shift, Left shift, Addition, Subtraction, Multiplication, XOR, AND and array/declaration indexing, respectively.
    - The operation body can at last return the value of a computed variable using the return statement. For example `< ret m >`, returns the value held in variable `m` inside the operation body.
    - In AES, we define operations to perform the Galois Field multiplication used during the MixColumn rounds.
    ```
    <operation>
        <func> < F_MUL2 ( a ) >
            < h : F_RS   ( a , 7 ) >
            < t : F_LS   ( a , 1 ) >
            < n : F_MUL  ( h , '0x1b' ) >
            < m : F_XOR  ( n , t ) >
            < ret m >
        </func>
        <func> < F_MUL3  ( a ) >
            < x : F_MUL2 ( a ) >
            < t : F_XOR  ( a , x ) >
            < ret t >
        </func>
    </operation>
    ```
3. **Rounds**
    - Rounds represents the series of round functions that constitutes the cipher. In AES, this consists of the SubBytes, ShiftRounds, MixColumns and AddRoundKey operations.
    - Each round specification consists of the round name (which must start with "F" followed by the round number in the sequence of operations), the linearity type of the round (linear/nonlinear), the type of the round (KEYXOR, SUBBYTE, MDS), followed by the *Parts* of the round within `<` and `/>`
    - Each part of the round, consists of a statement that assigns to a Round function value specified by the round name and an index into it.
    - For example, the following specifies an SBox round in AES. Each part in the round, specifies that the byte which is the result of the previous round (`F1`), needs to be passed as index into the SBOX declaration to get the result value of each index of the current round.
    ```
    < F2 > < nonlinear > < SUBBYTE > <
        < F2[0]   : F_LKUP( F1[0]  , SBOX ) >
        < F2[1]   : F_LKUP( F1[1]  , SBOX ) >
        < F2[2]   : F_LKUP( F1[2]  , SBOX ) >
        < F2[3]   : F_LKUP( F1[3]  , SBOX ) >
        < F2[4]   : F_LKUP( F1[4]  , SBOX ) >
        < F2[5]   : F_LKUP( F1[5]  , SBOX ) >
        < F2[6]   : F_LKUP( F1[6]  , SBOX ) >
        < F2[7]   : F_LKUP( F1[7]  , SBOX ) >
        < F2[8]   : F_LKUP( F1[8]  , SBOX ) >
        < F2[9]   : F_LKUP( F1[9]  , SBOX ) >
        < F2[10]  : F_LKUP( F1[10]  , SBOX ) >
        < F2[11]  : F_LKUP( F1[11]  , SBOX ) >
        < F2[12]  : F_LKUP( F1[12]  , SBOX ) >
        < F2[13]  : F_LKUP( F1[13]  , SBOX ) >
        < F2[14]  : F_LKUP( F1[14]  , SBOX ) >
        < F2[15]  : F_LKUP( F1[15]  , SBOX ) >
    />
    ```

    - In order to avoid repeatedly writing the same functions for each round of the cipher, CSL provides a `for` construct that expands into multiple rounds or parts (depending on whether it is used before round or part) during parsing.
        - For instance, `< for i in [2:38:4] >`, will be expanded to multiple rounds or parts, where i would be substituted with values from 2 to 38 in steps of 4. Note that the upper bound is inclusive. The steps is optional, and if not provided, will be considered as step of 1.
        - Inside the body of the round or part that is expanded, we use the `{  }` syntax to specify a substituition, i.e. a place where the loop variable value has to be substituted. The valid operations inside the substituition braces include addition, subtraction and multiplication with constants or loop variables.
        - There can only be one `for` construct for a given round, and a given part. But we can use a `for` construct of a part nested within a `for` construct of a round.
    - Below is an example of the Key XOR rounds of AES, specified using nested `For` construct. Here the round number is derived the from the loop variable `i` using the substituition `{i*4+1}`. And in the `F_LKUP` function the substituition `{i*16+j}` (which uses both loop variables) is used to find the index into the expanded key that needs to be used in the current round.
        ```
        < for i in [0:9] >
        < F{i*4+1} > < linear > < KEYXOR > <
            < for j in [0:15] >
            < F{i*4+1}[{j}]  : F_XOR( F{i*4}[{j}]  , F_LKUP( {i*16+j}  , EXPANDED_KEY ) ) >
        />
        ```

The complete specification of AES can be found [here](../specifications/AES_128.csl).

### Other language features

#### Bit slicing
- By default, every part in CSL operates on a byte. CSL also supports operating on certain bits within the byte using bit slicing suffix `_[`. For example, `F2[15]_[3]` represents the 3rd bit inside `F2[15]` (where 0 represents the least significant bit and 7 represents the most significant bit).
- Similarly, we can also specify a bit range to operate on consecutive bits of data. For example, `F2[15]_[6:4]` represents the three bit value equal to the bits starting from the 6th bit till the 4th bit of `F2[15]`. In other words, `F2[15]_[6:4]` is equivalent to `(F2[15]>>4) & 7`.
- Note that both the indices used in the bit slice are inclusive. CSL supports both order of specifying the indices, i.e. CSL treats `F2[15]_[6:4]` and `F2[15]_[4:6]` as the same.
