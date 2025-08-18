#################################################################################################
# This file contains Class definitions and Parsers for various elements of
# a Block cipher as defined in the Block Cipher Specification Language (BCSL)
#
# Each BCSL file (CipherSpec) has three parts
# - CipherSpec
#   - Declarations    : (Optional) Consists of lookup and data tables
#   - Operations      : (Optional) User defined functions that will be used in the rounds
#       - Statement   : Indiviual statements of the operation (also includes while, if-else)
#   - Rounds          : Rounds of the cipher
#       - Part        : Individual operations performed in the round (one for each value written)
#################################################################################################

#################################################################################################
# Parsers and the Grammar of BCSL
#################################################################################################
import re
from pyparsing import ParserElement, ParseResults, ParseException, Group, Forward
from pyparsing import Literal, OneOrMore, ZeroOrMore, Optional, oneOf
from pyparsing import Word, alphas, alphanums, nums, hexnums

def declarations_parser() -> ParserElement:
    """Returns a parser for Declarations (Constant lookup tables and data)"""
    name                = Word(alphas, alphanums + "_")
    declaration_name    = name
    declaration_len     = OneOrMore(Word(nums))
    declaration_value   = OneOrMore(Word(hexnums))
    declaration_values  = "{" + OneOrMore(declaration_value) + "}"
    declaration         = declaration_name + "[" + declaration_len + "]" + Optional(declaration_values)
    declaration         = declaration.add_parse_action(Declaration)
    declarations        = Literal("<declaration>").suppress()                                       \
                            + ZeroOrMore(declaration)                                               \
                            + Literal("</declaration>").suppress()
    return declarations

def operations_parser() -> ParserElement:
    """Returns a parser for Operations (User defined functions)"""
    name                = Word(alphas, alphanums + "_")
    function_name       = Group("F_" + name)
    constant            = (Literal("'").suppress() + Word(alphanums) + Literal("'").suppress())     \
                            ^ Word(nums)
    variable            = name + Optional("_[" + OneOrMore(Word(nums)) + "]")
    prototype_arg       = Group(variable ^ constant)
    prototype_args      = prototype_arg + ZeroOrMore(Literal(",").suppress() + prototype_arg)
    prototype           = function_name + "(" + Group(prototype_args) + ")"
    stmt                = Group("<" + variable + ":" + OneOrMore(prototype ^ variable) + ">")
    ret_stmt            = Group("ret" + variable)
    exit_stmt           = Group(Literal("<exit>"))

    predicate           = oneOf("F_EQ F_NEQ F_LE F_GE F_LT F_GT")
    condition           = predicate + "(" + variable + ")"
    loop                = Group(Literal("<repeat") + "(" + variable + ":" + condition + ")" + ">"
                                + OneOrMore(stmt)
                                + "</repeat>")
    if_else             = Group(Literal("<if") + "(" + variable + ":" + condition + ")" + ">"
                                + OneOrMore(stmt ^ ret_stmt ^ exit_stmt)
                                + Optional("<else>" + OneOrMore(stmt ^ ret_stmt ^ exit_stmt) )
                                + "</if>")
    operation           = Literal("<func>") + "<" + prototype + ">"                                 \
                            + ZeroOrMore(stmt ^ loop ^ if_else)                                     \
                            + Optional(ret_stmt ^ exit_stmt)                                        \
                            + "</func>"
    operation           = operation.add_parse_action(Operation)
    operations          = Literal("<operation>").suppress()                                         \
                            + ZeroOrMore(operation)                                                 \
                            + Literal("</operation>").suppress()
    return operations

def rounds_parser() -> ParserElement:
    """Returns a parser for Rounds of the cipher"""
    name                = Word(alphas, alphanums + "_")
    constant            = Group(Literal("'").suppress() + Word(alphanums)                           \
                                + Literal("'").suppress())                                          \
                            ^ Word(nums)
    function_name       = Group("F_" + name)
    linearity           = oneOf("linear nonlinear")
    round_type          = oneOf("KEYXOR SUBBYTE SWAP MDS DXOR FXOR CMP PREDICTPARITY FINDPARITY")
    bit_range           = (Word(nums) + ":" + Word(nums)) ^ Word(nums)
    generic_term        = (Optional(Word(nums) + Literal("*")) + name)                              \
                            ^ (name + Optional(Literal("*") + Word(nums)))                          \
                            ^ Word(nums)
    generic_expression  = Literal("{") + generic_term                                               \
                                + Optional(OneOrMore((Literal("+") ^ Literal("-")) + generic_term)) \
                                + Literal("}")
    part_name           = Group(name + Optional(generic_expression)                                 \
                                + Optional("[" + Word(nums) + "]")                                  \
                                + Optional("_[" + bit_range + "]"))
    function_call       = Forward()
    function_arg        = Group(function_call) | part_name | constant | Group(generic_expression)
    function_call       << function_name + "(" + Group(function_arg \
                                + ZeroOrMore(Literal(",").suppress() + function_arg)) + ")"
    part                = "<" + part_name + ":" + ( part_name ^ function_call ) + ">"
    part                = part.add_parse_action(Part)
    round_function_name = Group(Literal("F") + (Word(nums) ^ generic_expression))
    round               = "<" + round_function_name + ">" + "<" + linearity + ">"                   \
                            + "<" + round_type + ">"                                                \
                            + "<" + OneOrMore(part) + "/>"
    round               = round.add_parse_action(Round)
    generic_round       = Literal("<") + "for" + name + "in" +                                      \
                            "[" + Word(nums) + ":" + Word(nums) + Optional(":" + Word(nums)) + "]"  \
                            + Literal(">") + round
    generic_round       = generic_round.add_parse_action(GenericRound)
    rounds              = OneOrMore(round ^ generic_round)
    return rounds

def cipher_parser() -> ParserElement:
    """Returns a parser for the Cipher encoded in BCSL"""
    declarations    = declarations_parser()
    operations      = operations_parser()
    rounds          = rounds_parser()
    cipher          = Literal("<begin>").suppress()                                                 \
                        + Optional(declarations)                                                    \
                        + Optional(operations)                                                      \
                        + rounds                                                                    \
                        + Literal("<end>").suppress()
    cipher          = cipher.add_parse_action(CipherSpec)
    return cipher

#################################################################################################
# Class Definitions
#################################################################################################
class Declaration:
    """Represents a data declaration, which includes lookup tables and keys.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this operation
        name (str)  : Name of the table
        len (int) : Length of the table
        data (list[str]) : (Optional) List of hex data for initialization
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens = tokens
        self.name : str         = tokens[0]
        self.len  : int         = int(tokens[2])
        self.data : list[str]   = []
        if len(tokens) > 4 and tokens[4] == "{":
            for i in range(5, len(tokens)-1):
                self.data.append(tokens[i])
        if len(self.data) != 0 and self.len != len(self.data):
            print(f"Error: Declaration {self.name} has length {self.len}, but {len(self.data)} elements given")
            exit()

    def __str__(self) -> str:
        if len(self.data) == 0:
            return "Declaration: " + self.name + "[" + str(self.len) + "]"
        else:
            return "Declaration: " + self.name + "[" + str(self.len) + "] {" + ", ".join(self.data) + "}"

    def synthesize_c(self) -> str:
        if len(self.data) == 0:
            return "uint8_t " + self.name + "[" + str(self.len) + "];\n"
        else:
            return "uint8_t " + self.name + "[" + str(self.len) + "] = { "  \
                + ", ".join(["0x"+x for x in self.data]) + " };\n"

def evaluate_generic_expression(expression: str, variable: str, value: int, operators : list[str] = ["-", "+", "*"]):
    """Substitute the variable in the expression (for generic instantiation)"""
    if expression[0] == "{":
        assert expression[-1] == "}"
        expression = expression[1:-1]

    # Base case
    if expression == variable:
        return str(value)
    if len(operators) == 0:
        return expression

    # Recursive case
    operator = operators[0]
    if expression.find(operator) != -1:
        terms = [x.strip() for x in expression.split(operator)]
        for i in range(len(terms)):
            if terms[i] == variable:
                terms[i] = str(value)
            elif not terms[i].isdigit():
                terms[i] = evaluate_generic_expression(terms[i], variable, value, operators[1:])
        all_digits = True
        for i in range(len(terms)):
            if not terms[i].isdigit():
                all_digits = False
                break
        if all_digits:
            result = int(terms[0])
            for i in range(1,len(terms)):
                if operator == "-":
                    result = result - int(terms[i])
                elif operator == "+":
                    result = result + int(terms[i])
                elif operator == "*":
                    result = result * int(terms[i])
            return str(result)
        else:
            return operator.join(terms)
    return evaluate_generic_expression(expression, variable, value, operators[1:])

def instantiate_generics_on_string(string : str, generics_values : dict[str,int]):
    generic_expressions = re.findall(r"{[^}]+}", string)
    for variable in generics_values:
        value = generics_values[variable]
        for generic_expression in generic_expressions:
            string = re.sub(re.escape(generic_expression),  \
                    evaluate_generic_expression(generic_expression, variable, value),    \
                    string)
    return string

def synthesize_c_variable(tokens : ParserElement, generics_values : dict[str,int]) -> str:
    """Generate C code corresponding to the given variable"""
    value : str = "".join(tokens)
    if value[0] == "'" and value[-1] == "'":
        return value[1,-1]
    value = instantiate_generics_on_string(value, generics_values)
    if value.find("_[") != -1:
        separator_index : int = value.find("_[")
        bit_select : int = int(value[separator_index+2:-1])
        byte : str = value[:separator_index]
        return "((" + byte + ">>" + str(bit_select) + ")&1)"
    else:
        return value

def synthesize_c_statement_tokens(tokens : ParserElement, generics_values : dict[str,int] = {}) -> str:
    """Generate C code corresponding to the given statement tokens"""
    if len(tokens) > 1 and tokens[1] == "(":
        function_name = "".join(tokens[0])
        assert tokens[3] == ")"
        argument_tokens = tokens[2]
        assert function_name.startswith("F")

        if function_name == "F_RS":
            assert len(argument_tokens) == 2
            return "(" + synthesize_c_statement_tokens(argument_tokens[0], generics_values)  \
                + ">>" + synthesize_c_statement_tokens(argument_tokens[1], generics_values) + ")"
        elif function_name == "F_LS":
            assert len(argument_tokens) == 2
            return "(" + synthesize_c_statement_tokens(argument_tokens[0], generics_values)  \
                + "<<" + synthesize_c_statement_tokens(argument_tokens[1], generics_values) + ")"
        elif function_name == "F_MUL":
            assert len(argument_tokens) == 2
            return "(" + synthesize_c_statement_tokens(argument_tokens[0], generics_values)  \
                + "*" + synthesize_c_statement_tokens(argument_tokens[1], generics_values) + ")"
        elif function_name == "F_AND":
            assert len(argument_tokens) == 2
            return "(" + synthesize_c_statement_tokens(argument_tokens[0], generics_values)  \
                + "&" + synthesize_c_statement_tokens(argument_tokens[1], generics_values) + ")"
        elif function_name == "F_OR":
            assert len(argument_tokens) == 2
            return "(" + synthesize_c_statement_tokens(argument_tokens[0], generics_values)  \
                + "|" + synthesize_c_statement_tokens(argument_tokens[1], generics_values) + ")"
        elif function_name == "F_XOR":
            assert len(argument_tokens) == 2
            return "(" + synthesize_c_statement_tokens(argument_tokens[0], generics_values)  \
                + "^" + synthesize_c_statement_tokens(argument_tokens[1], generics_values) + ")"
        elif function_name == "F_LKUP":
            assert len(argument_tokens) == 2
            return synthesize_c_statement_tokens(argument_tokens[1], generics_values)  \
                + "[" + synthesize_c_variable(argument_tokens[0], generics_values) + "]"
        else:
            assert function_name.startswith("F_")
            return function_name[2:] + "(" + ", ".join(  \
                [synthesize_c_statement_tokens(x, generics_values) for x in argument_tokens]) + ")"
    else:
        if isinstance(tokens, list):
            assert len(tokens) == 1 and isinstance(tokens[0], ParseResults)
            tokens = tokens[0]
        return synthesize_c_variable(tokens, generics_values)

class Statement:
    """Represents a statement in a User-defined function.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this statement
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens = tokens
    def __str__(self) -> str:
        return "".join([str(x) for x in self.tokens])

    def synthesize_c(self) -> str:
        if self.tokens[0] == "ret":
            return "\treturn " + self.tokens[1] + ";\n"
        elif self.tokens[0] == "<":
            assert self.tokens[2] == ":"
            assert self.tokens[-1] == ">"
            output_variable = self.tokens[1]
            statement_tokens = self.tokens[3:-1]
            return "\tuint8_t " + output_variable + " = "   \
                + synthesize_c_statement_tokens(statement_tokens) + ";\n"
        else:
            # FIXME Handle if-else and loop
            print("Error: Unhandled statement type: ", end="")
            print(self.tokens)
            assert False

class Operation:
    """Represents a User-defined function used in the cipher.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this operation
        name (str)  : Name of the function
        arguments (list[str]) : Argument names
        statements (list[Statement]) : List of statements in the function
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens = tokens
        self.name : str                     = "".join([str(x) for x in tokens[2]])
        self.arguments : list[str]          = []
        for argument_tokens in tokens[4]:
            self.arguments.append("".join([str(x) for x in argument_tokens]))
        self.statements : list[Statement]   = []
        for i in range(7, len(tokens) - 1):
            self.statements.append(Statement(tokens[i]))
        if not self.name.startswith("F_"):
            print(f"Error: Opertion name {self.name} must have 'F_' prefix")
            exit()

    def __str__(self) -> str:
        return self.name + "(" + ", ".join(self.arguments) + ") {\n\t"      \
                + "\n\t".join([str(x) for x in self.statements]) + "\n}"

    def synthesize_c(self) -> str:
        output = "uint8_t " + self.name[2:] + " (" + ", ".join(["uint8_t "+x for x in self.arguments]) + ") {\n"
        for statement in self.statements:
            output += statement.synthesize_c()
        output += "}\n"
        return output

class Part:
    """Represents the suboperations that are part of a round in the cipher.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this Part
        output_value (str) : The value to which this Part is assigning
        function_tokens (list[ParserElement]) : (Optional) Parser tokens corresponding to the function
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens                     = tokens
        assert self.tokens[0] == "<"
        assert self.tokens[2] == ":"
        self.output_value   : str       = "".join([str(x) for x in tokens[1]])
        self.function_tokens            = tokens[3:len(tokens)-1]
        self.generics_values : dict[str,int]    = {}

    def __str__(self) -> str:
        return self.output_value + " = F(" + ",".join(self.input_values) + ")"

    def instantiate_generics(self, variable : str, value : int):
        """Generates a new Round by substituiting the given value for the given variable"""
        self.output_value = instantiate_generics_on_string(self.output_value, {variable: value})
        self.generics_values[variable] = value

    # FIXME We haven't handled the case where the LHS has a bit slice
    def synthesize_c(self) -> str:
        return self.output_value + " = " + synthesize_c_statement_tokens(self.function_tokens, self.generics_values) + ";"

class Round:
    """Represents a Round in the cipher.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this round
        name (str)  : Name of the round
        linearity (str)  : Linearity of the round
        type (str)  : Type of the round
        parts (list[Part])  : The individual operations performed in this round
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens = tokens
        self.name       : str           = "".join([str(x) for x in tokens[1]])
        self.linearity  : str           = tokens[4]
        self.type       : str           = tokens[7]
        self.parts      : list[Part]    = []
        for i in range(10, len(tokens) - 1):
            self.parts.append(tokens[i])

    def __str__(self) -> str:
        return f"{self.name} : {self.linearity} : {self.type}\n\t" + "\n\t".join([str(x) for x in self.parts])

    def instantiate_generics(self, variable : str, value : int):
        """Generates a new Round by substituiting the given value for the given variable
        """
        self.name = instantiate_generics_on_string(self.name, {variable: value})
        new_parts = []
        for part in self.parts:
            new_part = Part(part.tokens)
            new_part.instantiate_generics(variable, value)
            new_parts.append(new_part)
        self.parts = new_parts

    def synthesize_c(self) -> str:
        output = "\t// Round " + self.name + "\n\t"
        output += "\n\t".join([part.synthesize_c() for part in self.parts]) + "\n"
        return output

class GenericRound:
    """Represents a set of Rounds in the cipher, that are generated from the For construct.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this generic round
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens = tokens

    def generate_rounds(self) -> list[Round]:
        assert self.tokens[0] == "<"
        assert self.tokens[1] == "for"
        iter_variable = str(self.tokens[2])
        assert self.tokens[3] == "in"
        assert self.tokens[4] == "["
        iter_start = int(self.tokens[5])
        assert self.tokens[6] == ":"
        iter_end = int(self.tokens[7])
        iter_step = 1
        if self.tokens[8] == ":":
            iter_step = int(self.tokens[9])
        round = self.tokens[-1]

        # Generating rounds
        new_rounds = []
        for iter_value in range(iter_start,iter_end+1,iter_step):
            new_round = Round(round.tokens)
            new_round.instantiate_generics(iter_variable, iter_value)
            new_rounds.append(new_round)
        return new_rounds

class CipherSpec:
    """Represents a Specification of a Block Cipher.

    Attributes:
        filename (str)  : Filename of the BCSL specification file
        declarations (list[Declaration]) : Declarations (data and lookup tables) of the cipher
        operations (list[Operation]) : Operations (User defined functions) of the cipher
        rounds (list[Round]) : Rounds of the cipher
    """

    def __init__(self, tokens: ParserElement) -> None:
        """Represents a Cipher Specification

        Attributes:
            tokens (ParserElement) : Parser tokens corresponding to this round
            declarations (list[Declaration])    : Declarations of the cipher
            operations (list[Operation])        : Operations of the cipher
            rounds (list[Round])                : Rounds of the cipher
        """
        self.tokens                             = tokens
        self.declarations   : list[Declaration] = []
        self.operations     : list[Operation]   = []
        self.rounds         : list[Round]       = []
        for token in self.tokens:
            if (isinstance(token, Declaration)):
                self.declarations.append(token)
            elif (isinstance(token, Operation)):
                self.operations.append(token)
            elif (isinstance(token, Round)):
                self.rounds.append(token)
            elif (isinstance(token, GenericRound)):
                self.rounds.extend(token.generate_rounds())
            else:
                assert False, "Error in parsing"
        self.rounds.sort(key=lambda x: int(x.name[1:]))

    def __str__(self) -> str:
        output = ""
        if len(self.declarations) > 0:
            output += "\n\n# Declarations  :\n" + "\n".join([str(x) for x in self.declarations])
        if len(self.operations) > 0:
            output += "\n\n# Operations    :\n" + "\n".join([str(x) for x in self.operations])
        output += "\n\n# Rounds        :\n" + "\n".join([str(x) for x in self.rounds])
        return output

    def synthesize_c(self) -> str:
        output = "#include<stdio.h>\n#include<stdlib.h>\n#include<math.h>\n#include<stdint.h>\n\n"
        output += "\n".join([declaration.synthesize_c() for declaration in self.declarations]) + "\n"
        output += "\n".join([operation.synthesize_c() for operation in self.operations]) + "\n"

        output += "void encrypt(uint8_t F0[16], uint8_t ciphertext[16]) {\n"
        output += "\tuint8_t " + ", ".join([round.name+"[64]" for round in self.rounds])+ ";\n" # FIXME Length
        output += "\n".join([round.synthesize_c() for round in self.rounds]) + "\n"

        for i in range(len(self.rounds) + 1):
            output += "\tprintf(\"\\nF" + str(i) + "\\t\");\n\tfor (int i=0; i<16; i++)\n\t\tprintf(\"%x \", F" + str(i) + "[i]);\n"
        output += "\tfor (int i=0; i<16; i++)\n\t\tciphertext[i] = F" + str(len(self.rounds)) + "[i];\n"
        output += "}\n\n"

        output += "int main() {\n"
        output += "\tuint8_t plaintext[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05 , 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};\n\tuint8_t ciphertext[16];\n\tencrypt(plaintext, ciphertext);\n\tprintf(\"\\nFinal\\t\");\n\tfor (int i=0;i<16;i++)\n\t\tprintf(\"%x \", ciphertext[i]);\n"
        output += "}"

        return output
