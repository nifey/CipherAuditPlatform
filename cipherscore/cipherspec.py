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
from pyparsing import ParserElement, ParseException, Group, Forward
from pyparsing import Literal, OneOrMore, ZeroOrMore, Optional, oneOf
from pyparsing import Word, alphas, alphanums, nums, hexnums

def declarations_parser() -> ParserElement:
    """"Returns a parser for Declarations (Constant lookup tables and data)"""
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
    """"Returns a parser for Operations (User defined functions)"""
    name                = Word(alphas, alphanums + "_")
    function_name       = Group("F_" + name)
    constant            = (Literal("'") + Word(alphanums) + Literal("'")) ^ Word(nums)
    variable            = name
    variable_bit        = variable + "_[" + OneOrMore(Word(nums)) + "]"
    prototype_arg       = Group(variable_bit ^ variable ^ constant)
    prototype_args      = prototype_arg + ZeroOrMore(Literal(",").suppress() + prototype_arg)
    prototype           = function_name + "(" + Group(prototype_args) + ")"
    variable_used       = Group(Optional("(") + (variable_bit ^ variable)
                                + ZeroOrMore("," + (variable_bit ^ variable)) + Optional(")"))      \
                            + ":" + prototype

    stmt                = Group("<" + variable + ":" + "{"
                                + OneOrMore(variable_bit ^ variable_used ^ variable)
                                + "}" + ">")
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
    operations          = Literal("<operations>").suppress()                                        \
                            + ZeroOrMore(operation)                                                 \
                            + Literal("</operations>").suppress()
    return operations

def rounds_parser() -> ParserElement:
    """"Returns a parser for Rounds of the cipher"""
    name                = Word(alphas, alphanums + "_")
    constant            = (Literal("'") + Word(alphanums) + Literal("'")) ^ Word(nums)
    function_name       = Group("F_" + name)
    linearity           = oneOf("linear nonlinear")
    round_function_name = Group(Literal("F") + Word(nums))
    round_type          = oneOf("KEYXOR SUBBYTE SWAP MDS DXOR FXOR CMP PREDICTPARITY FINDPARITY")
    bit_range           = (Word(nums) + ":" + Word(nums)) ^ Word(nums)
    part_name           = Group(name + Optional("[" + Word(nums) + "]")
                                + Optional("_[" + bit_range + "]"))
    function_call       = Forward()
    function_arg        = Group(function_call) | part_name | constant
    function_call       << function_name + Group("(" + function_arg 
                                                 + ZeroOrMore(Literal(",").suppress()
                                                              + function_arg) + ")")
    part_used           = Optional("(")                                                             \
                            + Group(part_name + ZeroOrMore(Literal(",").suppress()
                                                           + part_name))                            \
                            + Optional(")") + Optional(":" + function_call)
    part                = "<" + part_name + ":" + "{" + part_used + "}" + ">"
    part                = part.add_parse_action(Part)
    round               = "<" + round_function_name + ">" + "<" + linearity + ">"                   \
                            + "<" + round_type + ">"                                                \
                            + "<" + OneOrMore(part) + "/>"
    round               = round.add_parse_action(Round)
    rounds              = OneOrMore(round)
    return rounds

def cipher_parser() -> ParserElement:
    """"Returns a parser for the Cipher encoded in BCSL"""
    declarations    = declarations_parser()
    operations      = operations_parser()
    rounds          = rounds_parser()
    cipher          = Literal("<begin>").suppress()                                                 \
                        + Optional(declarations)                                                    \
                        + Optional(operations)                                                      \
                        + rounds                                                                    \
                        + Literal("<end>").suppress()
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

class Statement:
    """Represents a statement in a User-defined function.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this statement
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens = tokens
    def __str__(self) -> str:
        return "".join([str(x) for x in self.tokens])

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

    def __str__(self) -> str:
        return self.name + "(" + ", ".join(self.arguments) + ") {\n\t"      \
                + "\n\t".join([str(x) for x in self.statements]) + "\n}"

class Part:
    """Represents the suboperations that are part of a round in the cipher.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this Part
        output_value (str) : The value to which this Part is assigning
        input_values (list[str]) : The values which are input to the evaluated functions
        function_tokens (list[ParserElement]) : (Optional) Parser tokens corresponding to the function
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens                     = tokens
        self.output_value   : str       = "".join([str(x) for x in tokens[1]])
        self.input_values   : list[str] = []
        for input_value_token in tokens[5]:
            self.input_values.append("".join([str(x) for x in input_value_token]))
        self.function_tokens            = []
        if str(tokens[7]) == ":":
            self.function_tokens        = tokens[8:len(tokens)-2]

    def __str__(self) -> str:
        return self.output_value + " = F(" + ",".join(self.input_values) + ")"

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

class CipherSpec:
    """Represents a Specification of a Block Cipher.

    Attributes:
        filename (str)  : Filename of the BCSL specification file
        declarations (list[Declaration]) : Declarations (data and lookup tables) of the cipher
        operations (list[Operation]) : Operations (User defined functions) of the cipher
        rounds (list[Round]) : Rounds of the cipher
    """

    def __init__(self, filename: str) -> None:
        """Reads the specification from the given file (in Block Cipher Specification Language), 
        and constructs the CipherSpec object from it.

        Args:
            filename (str) : Filename of the BCSL specification file
        """
        self.filename       : str = filename
        self.declarations   : list[Declaration] = []
        self.operations     : list[Operation]   = []
        self.rounds         : list[Round]       = []
        try:
            self.tokens = cipher_parser().parseFile(filename)
            for token in self.tokens:
                if (isinstance(token, Declaration)):
                    self.declarations.append(token)
                elif (isinstance(token, Operation)):
                    self.operations.append(token)
                elif (isinstance(token, Round)):
                    self.rounds.append(token)
                else:
                    assert False, "Error in parsing"
        except ParseException as e:
            print("Parse error: ", end="")
            print(e)
            exit()

    def __str__(self) -> str:
        output = "# Filename      : " + self.filename
        if len(self.declarations) > 0:
            output += "\n\n# Declarations  :\n" + "\n".join([str(x) for x in self.declarations])
        if len(self.operations) > 0:
            output += "\n\n# Operations    :\n" + "\n".join([str(x) for x in self.operations])
        output += "\n\n# Rounds        :\n" + "\n".join([str(x) for x in self.rounds])
        return output
