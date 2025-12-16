#################################################################################################
# This file contains Class definitions and Parsers for various elements of
# a Block cipher as defined in the Cipher Specification Language (CSL)
#
# Each CSL file (CipherSpec) has three parts
# - CipherSpec
#   - Declarations    : (Optional) Consists of lookup and data tables
#   - Operations      : (Optional) User defined functions that will be used in the rounds
#       - Statement   : Indiviual statements of the operation (also includes while, if-else)
#   - Rounds          : Rounds of the cipher
#       - Part        : Individual operations performed in the round (one for each value written)
#################################################################################################

#################################################################################################
# Parsers and the Grammar of CSL
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
    stmt                = Forward()
    assign_stmt         = Group("<" + variable + ":" + OneOrMore(prototype ^ variable ^ constant) + ">")
    ret_stmt            = Group(Literal("<") + "ret" + variable + Literal(">"))
    exit_stmt           = Group(Literal("<exit>"))

    condition           = variable + oneOf("EQ NE LE GE LT GT") + (variable ^ constant)
    loop                = Group(Literal("<") + Literal("while") + condition + ">"                   \
                                + Group(OneOrMore(stmt))                                            \
                                + "</while>")
    if_else             = Group(Literal("<") + Literal ("if") + condition + ">"                     \
                                + Group(OneOrMore(stmt))                                            \
                                + Optional("<else>" + Group(OneOrMore(stmt)))                       \
                                + "</if>")
    stmt                <<= if_else ^ loop ^ assign_stmt ^ ret_stmt ^ exit_stmt
    operation           = Literal("<func>") + "<" + prototype + ">"                                 \
                            + ZeroOrMore(stmt)                                                      \
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
    generic_term        = (Optional(Word(nums) + Literal("*")) + name)                              \
                            ^ (name + Optional(Literal("*") + Word(nums)))                          \
                            ^ Word(nums)
    generic_expression  = Literal("{") + generic_term                                               \
                                + Optional(OneOrMore((Literal("+") ^ Literal("-")) + generic_term)) \
                                + Literal("}")
    generic_number      = Word(nums) ^ generic_expression
    bit_range           = (generic_number + ":" + generic_number) ^ generic_number
    part_name           = Group(name + Optional(generic_expression)                                 \
                                + Optional("[" + generic_number + "]")                              \
                                + Optional("_[" + bit_range + "]"))
    function_call       = Forward()
    function_arg        = Group(function_call) | part_name | constant | Group(generic_expression)
    function_call       << function_name + "(" + Group(function_arg \
                                + ZeroOrMore(Literal(",").suppress() + function_arg)) + ")"
    part                = "<" + part_name + ":" + ( part_name ^ function_call ) + ">"
    part                = part.add_parse_action(Part)
    generic_part        = Literal("<") + "for" + name + "in" +                                      \
                            "[" + Word(nums) + ":" + Word(nums) + Optional(":" + Word(nums)) + "]"  \
                            + Literal(">") + part
    generic_part       = generic_part.add_parse_action(GenericPart)
    round_function_name = Group(Literal("F") + (Word(nums) ^ generic_expression))
    round               = "<" + round_function_name + ">" + "<" + linearity + ">"                   \
                            + "<" + round_type + ">"                                                \
                            + "<" + OneOrMore(part ^ generic_part) + "/>"
    round               = round.add_parse_action(Round)
    generic_round       = Literal("<") + "for" + name + "in" +                                      \
                            "[" + Word(nums) + ":" + Word(nums) + Optional(":" + Word(nums)) + "]"  \
                            + Literal(">") + round
    generic_round       = generic_round.add_parse_action(GenericRound)
    rounds              = OneOrMore(round ^ generic_round)
    return rounds

def cipher_parser() -> ParserElement:
    """Returns a parser for the Cipher encoded in CSL"""
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
            return "uint64_t " + self.name + "[" + str(self.len) + "];\n"
        else:
            return "uint64_t " + self.name + "[" + str(self.len) + "] = { "  \
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
    for generic_expression in generic_expressions:
        evaluated_expression = generic_expression
        for variable in generics_values:
            value = generics_values[variable]
            evaluated_expression =  evaluate_generic_expression(evaluated_expression, variable, value)
        if evaluated_expression.isdigit():
            string = string.replace(generic_expression, evaluated_expression)
        else:
            # This expression isn't fully evaluted, and has to be considered again later
            string = string.replace(generic_expression, "{" + evaluated_expression + "}")
    return string

def parse_bit_range(value) -> (str, int, int):
    """Parse bit range and return part name, start, end bit index"""
    if value.find("_[") == -1:
        assert False
    separator_index : int = value.find("_[")
    word : str = value[:separator_index]
    bit_range = value[separator_index+2:-1]
    if bit_range.find(":") != -1:
        # Bit range select
        split_index     : int = bit_range.find(":")
        bit_select_msb  : int = int(bit_range[:split_index])
        bit_select_lsb  : int = int(bit_range[split_index+1:])
        if bit_select_msb < bit_select_lsb: # We support both order indexing
            bit_select_msb, bit_select_lsb = bit_select_lsb, bit_select_msb
    else:
        # Single bit select
        bit_select_msb  : int = int(bit_range)
        bit_select_lsb  : int = bit_select_msb
    return word, bit_select_msb, bit_select_lsb

def synthesize_c_variable(tokens : ParserElement, generics_values : dict[str,int] = {}) -> str:
    """Generate C code corresponding to the given variable"""
    value : str = "".join(tokens)
    if value[0] == "'" and value[-1] == "'":
        return value[1,-1]
    value = instantiate_generics_on_string(value, generics_values)
    if value.find("_[") != -1:
        word, bit_select_msb, bit_select_lsb = parse_bit_range(value)
        if bit_select_msb == bit_select_lsb:
            # Single bit select
            return "BIT_SELECT(" + word + "," + str(bit_select_lsb) + ")"
        else:
            # Bit range select
            return "BITRANGE_SELECT(" + word + "," + str(bit_select_msb) + \
                    "," + str(bit_select_lsb) + ")"
    else:
        return value

binary_function_to_symbol_map = {
        "F_ADD": "+",   "F_SUB": "-",
        "F_MUL": "*",   "F_DIV": "/",   "F_MOD": "%",
        "F_RS" : ">>",  "F_LS" : "<<",
        "F_XOR": "^",   "F_AND": "&",   "F_OR": "|",
        }
binary_predicate_to_symbol_map = {"EQ": "==","NE": "!=","GT": ">", "LT": "<","GE": ">=","LE": "<="}
def synthesize_c_statement_tokens(tokens : ParserElement, generics_values : dict[str,int] = {},
                                  variable_set : set[str] = set()) -> str:
    """Generate C code corresponding to the given statement tokens"""
    if tokens[0] == "<" and tokens[1] == "ret":
        assert tokens[3] == ">"
        return "\treturn " + tokens[2] + ";\n"
    elif tokens[0] == "<" and tokens[2] == ":":
        assert tokens[-1] == ">"
        output_variable = tokens[1]
        statement_tokens = tokens[3:-1]
        variable_set.add(output_variable)
        return "\t" + output_variable + " = " \
                + synthesize_c_statement_tokens(statement_tokens, generics_values, variable_set) + ";\n"
    elif tokens[0] == "<" and  tokens[1] == "if":
        assert tokens[5] == ">"
        result = []
        result.append("if (" + synthesize_c_variable(tokens[2])                             \
                      + " " + binary_predicate_to_symbol_map[tokens[3]] + " "               \
                      + synthesize_c_variable(tokens[4]) + ") {")
        for token in tokens[6]:
            substatements = synthesize_c_statement_tokens(token, generics_values, variable_set).split("\n")
            if substatements[-1] == "":
                substatements = substatements[:-1]
            result.extend(substatements)
        if tokens[7] == "<else>":
            result.append("} else {")
            for token in tokens[8]:
                substatements = synthesize_c_statement_tokens(token, generics_values, variable_set).split("\n")
                if substatements[-1] == "":
                    substatements = substatements[:-1]
                result.extend(substatements)
        result.append("}\n")
        return "\t" + "\n\t".join(result)
    elif tokens[0] == "<" and  tokens[1] == "while":
        assert tokens[5] == ">"
        result = []
        result.append("while (" + synthesize_c_variable(tokens[2])                          \
                      + " " + binary_predicate_to_symbol_map[tokens[3]] + " "               \
                      + synthesize_c_variable(tokens[4]) + ") {")
        for token in tokens[6]:
            substatements = synthesize_c_statement_tokens(token, generics_values, variable_set).split("\n")
            if substatements[-1] == "":
                substatements = substatements[:-1]
            result.extend(substatements)
        result.append("}\n")
        return "\t" + "\n\t".join(result)
    elif len(tokens) > 1 and tokens[1] == "(":
        function_name = "".join(tokens[0])
        assert tokens[3] == ")"
        argument_tokens = tokens[2]
        assert function_name.startswith("F")

        if function_name in binary_function_to_symbol_map:
            return "(" + synthesize_c_statement_tokens(argument_tokens[0], generics_values, variable_set) \
                + binary_function_to_symbol_map[function_name]                              \
                + synthesize_c_statement_tokens(argument_tokens[1], generics_values, variable_set) + ")"
        elif function_name == "F_LKUP":
            return synthesize_c_statement_tokens(argument_tokens[1], generics_values, variable_set)  \
                + "[" + synthesize_c_variable(argument_tokens[0], generics_values) + "]"
        else:
            assert function_name.startswith("F_")
            return function_name[2:] + "(" + ", ".join(  \
                [synthesize_c_statement_tokens(x, generics_values, variable_set) for x in argument_tokens]) + ")"
    elif isinstance(tokens, list):
        return "".join([synthesize_c_statement_tokens(t, generics_values, variable_set) for t in tokens])
    else:
        return synthesize_c_variable(tokens, generics_values)

def get_all_function_calls(tokens : ParserElement) -> list[(str,int)]:
    """Return all function calls and number of arguments passed for validation"""
    call_list = []
    if tokens[0] == "<" and tokens[1] == "ret":
        pass
    elif tokens[0] == "<" and tokens[2] == ":":
        assert tokens[-1] == ">"
        output_variable = tokens[1]
        statement_tokens = tokens[3:-1]
        call_list.extend(get_all_function_calls(statement_tokens))
    elif len(tokens) > 1 and tokens[1] == "(":
        function_name = "".join(tokens[0])
        assert tokens[3] == ")"
        argument_tokens = tokens[2]
        assert function_name.startswith("F")
        call_list.append((function_name, len(argument_tokens)))
    elif isinstance(tokens, list):
        for token in tokens:
            call_list.extend(get_all_function_calls(token))
    return call_list

def get_all_input_values(tokens : ParserElement, generics_values : dict[str,int] = {}) -> set[str]:
    """Return all the input round parts corresponding to the given statement tokens"""
    input_value_set = set()
    if tokens[0] == "<" and tokens[1] == "ret":
        pass
    elif tokens[0] == "<" and tokens[2] == ":":
        assert tokens[-1] == ">"
        output_variable = tokens[1]
        statement_tokens = tokens[3:-1]
        input_value_set.update(get_all_input_values(statement_tokens, generics_values))
    elif tokens[0] == "<" and tokens[5] == ">" and (tokens[1] == "if" or tokens[1] == "while"):
        print("If and while statements are not allowed inside round functions")
        assert False
    elif len(tokens) > 1 and tokens[1] == "(":
        function_name = "".join(tokens[0])
        assert tokens[3] == ")"
        argument_tokens = tokens[2]
        assert function_name.startswith("F")

        if function_name in binary_function_to_symbol_map:
            input_value_set.update(get_all_input_values(argument_tokens[0], generics_values))
            input_value_set.update(get_all_input_values(argument_tokens[1], generics_values))
        elif function_name == "F_LKUP":
            input_value_set.update(get_all_input_values(argument_tokens[1], generics_values))
            input_value_set.add(synthesize_c_variable(argument_tokens[0], generics_values))
        else:
            assert function_name.startswith("F_")
            for token in argument_tokens:
                input_value_set.update(get_all_input_values(token, generics_values))
    elif isinstance(tokens, list):
        for token in tokens:
            input_value_set.update(get_all_input_values(token, generics_values))
    else:
        input_value_set.add(synthesize_c_variable(tokens, generics_values))
    return input_value_set

class Statement:
    """Represents a statement in a User-defined function.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this statement
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens = tokens
    def __str__(self) -> str:
        return "".join([str(x) for x in self.tokens])

    def synthesize_c(self, variable_set : set[str]) -> str:
        return synthesize_c_statement_tokens(self.tokens, {}, variable_set)

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
        output = "uint64_t " + self.name[2:] + " (" + ", ".join(["uint64_t "+x for x in self.arguments]) + ") {\n"
        variable_set = set()
        statement_string = ""
        for statement in self.statements:
            statement_string += statement.synthesize_c(variable_set)
        # Declare the required variables before adding the statement synthesis
        if len(variable_set) > 0:
            output += "\tuint64_t " + ", ".join(sorted(variable_set)) + ";\n"
        output += statement_string
        output += "}\n"
        return output

class Part:
    """Represents the suboperations that are part of a round in the cipher.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this Part
        output_value (str) : The value to which this Part is assigning
        function_tokens (list[ParserElement]) : (Optional) Parser tokens corresponding to the function
        generics_values (dict[str,int]) : Map from generic variable to instantiating value
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens                     = tokens
        assert self.tokens[0] == "<"
        assert self.tokens[2] == ":"
        self.output_value   : str       = "".join([str(x) for x in tokens[1]])
        self.function_tokens            = tokens[3:len(tokens)-1]
        self.generics_values : dict[str,int]    = {}

    def __str__(self) -> str:
        return self.synthesize_c()

    def instantiate_generics(self, variable : str, value : int):
        """Generates a new Round by substituiting the given value for the given variable"""
        self.generics_values[variable] = value
        self.output_value = instantiate_generics_on_string(self.output_value, self.generics_values)

    def get_output_value(self):
        return self.output_value

    def get_input_values(self):
        input_values = set()
        for value in get_all_input_values(self.function_tokens, self.generics_values):
            for regex_match in re.findall(r"F[0-9]+\[[0-9]+\]", value):
                input_values.add(regex_match)
        return input_values

    def get_function_calls(self):
        return get_all_function_calls(self.function_tokens)

    def synthesize_c(self) -> str:
        if self.output_value.find("_[") != -1:
            # We have to handle bit select on the output value differently 
            # when compared to bit handling in synthesize_c_variable
            rhs_statement = synthesize_c_statement_tokens(self.function_tokens, self.generics_values)
            word, bit_select_msb, bit_select_lsb = parse_bit_range(self.output_value)
            if bit_select_msb == bit_select_lsb:
                # Single bit select
                bit_select_mask         = "BIT("+str(bit_select_lsb)+")"
                bit_select_inverse_mask = "(BITMASK(63)^"+str(bit_select_mask)+")" # 64 bit words
            else:
                # Bit range select
                bit_select_mask         = "BITRANGE_BITMASK("+str(bit_select_msb)+","+str(bit_select_lsb)+")"
                bit_select_inverse_mask = "(BITMASK(63)^"+str(bit_select_mask)+")" # 64 bit words
            return word + " = (" + word + " & " + bit_select_inverse_mask + ") | " + \
                    "((" + rhs_statement + "<<" + str(bit_select_lsb)+ ") & " + bit_select_mask + ");"
        else:
            return self.output_value + " = " + \
                    synthesize_c_statement_tokens(self.function_tokens, self.generics_values) + ";"

class GenericPart:
    """Represents a set of Parts in a Cipher Round, that are generated from the For construct.

    Attributes:
        tokens (ParserElement) : Parser tokens corresponding to this generic part
    """

    def __init__(self, tokens: ParserElement) -> None:
        self.tokens = tokens

    def generate_parts(self) -> list[Part]:
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
        part = self.tokens[-1]

        # Generating parts
        new_parts = []
        for iter_value in range(iter_start,iter_end+1,iter_step):
            new_part = Part(part.tokens)
            new_part.instantiate_generics(iter_variable, iter_value)
            new_parts.append(new_part)
        return new_parts

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
            if isinstance(tokens[i], GenericPart):
                # Expand any generic parts
                self.parts.extend(tokens[i].generate_parts())
            else:
                self.parts.append(tokens[i])

    def __str__(self) -> str:
        return f"{self.name} : {self.linearity} : {self.type}\n\t" + "\n\t".join([str(x) for x in self.parts])

    def instantiate_generics(self, variable : str, value : int):
        """Generates a new Round by substituiting the given value for the given variable
        """
        self.name = instantiate_generics_on_string(self.name, {variable: value})
        new_parts = []
        for i in range(10, len(self.tokens) - 1):
            if isinstance(self.tokens[i], GenericPart):
                # Expand any generic parts. Here we don't have to create a copy
                # because generate_parts creates copies for us, possibly instantiating part-level generics
                for new_part in self.tokens[i].generate_parts():
                    new_part.instantiate_generics(variable, value)
                    new_parts.append(new_part)
            else:
                new_part = Part(self.tokens[i].tokens)
                new_part.instantiate_generics(variable, value)
                new_parts.append(new_part)
        self.parts = new_parts

    def length(self) -> int:
        max_index = 0
        for part in self.parts:
            output_value = part.get_output_value()
            index = int(re.match(r'F[0-9]+\[([0-9]+)\]', output_value).groups()[0])
            if index > max_index:
                max_index = index
        return max_index + 1

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
        filename (str)  : Filename of the CSL specification file
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

        ########################################################
        # Perform validation checks on the cipher specification
        ########################################################
        operation_argument_count = {}
        for operation in self.operations:
            function_name = operation.name
            # Check if a given function/operation name doesn't collide 
            # with inbuilt or other function, and records the number of 
            # arguments to be checked later when it is called
            if function_name in binary_function_to_symbol_map:
                print(f"Operation name {function_name} collides with inbuilt function name")
                exit()
            elif function_name in operation_argument_count:
                print(f"Operation name {function_name} already defined")
                exit()
            operation_argument_count[function_name] = len(operation.arguments)

        round_output_values = {}
        for round in self.rounds:
            round_name = round.name
            round_output_values[round_name] = []
            for part in round.parts:
                # Check if each round only writes to it's own data
                if not part.get_output_value().startswith(round_name):
                    print("Parts of a round should only write to values of the same round")
                    print(f"Part {part} should write to {round_name}")
                    exit()
                round_output_values[round_name].append(part.get_output_value())

                # Check if all the function calls are to valid operations / inbuilt functions
                # And also check if the right number of arguments have been provided
                for function_name, num_args in part.get_function_calls():
                    if function_name in binary_function_to_symbol_map:
                        if num_args != 2:
                            print(f"Inbuilt binary function {function_name} takes 2 arguments, {num_args} provided")
                            exit()
                    elif function_name == "F_LKUP":
                        if num_args != 2:
                            print(f"Lookup function F_LKUP takes 2 arguments, {num_args} provided")
                            exit()
                    elif function_name in operation_argument_count:
                        required_args = operation_argument_count[function_name]
                        if num_args != required_args:
                            print(f"Function {function_name} takes {required_args} arguments, {num_args} provided")
                            exit()
                    else:
                        print(f"Function {function_name} is not defined")
                        exit()

            # Check if the output of the rounds are to non overlapping data,
            # i.e. we don't expect two writes to the same bits of data
            output_index_value = {}
            for output_value in round_output_values[round_name]:
                if output_value.find("_[") != -1:
                    word, bit_select_msb, bit_select_lsb = parse_bit_range(output_value)
                    assert bit_select_lsb >= 0 and bit_select_lsb < 8
                    assert bit_select_msb >= 0 and bit_select_msb < 8
                else:
                    word = output_value
                    bit_select_lsb = 0
                    bit_select_msb = 7
                index = int(word.split("[")[1][:-1])
                mask = (1<<(bit_select_msb+1)) - (1<<bit_select_lsb)
                if index not in output_index_value:
                    output_index_value[index] = {}
                # Check if this overlaps with already saved output value
                for old_ouput_value in output_index_value[index]:
                    if output_index_value[index][old_ouput_value] & mask != 0:
                        print(f"{old_ouput_value} and {output_value} write to the same bits")
                        exit()
                output_index_value[index][output_value] = mask

            # FIXME Also check if the any previous round values are used (not future). 
            # And that the used value has been defined in the previous round

    def input_length(self) -> int:
        """Return the number of words that the cipher takes as (plaintext) input"""
        max_index = 0
        for part in self.rounds[0].parts:
            for value in part.get_input_values():
                index = int(re.match(r'F[0-9]+\[([0-9]+)\]', value).groups()[0])
                if index > max_index:
                    max_index = index
        return max_index + 1

    def __str__(self) -> str:
        output = ""
        if len(self.declarations) > 0:
            output += "\n\n# Declarations  :\n" + "\n".join([str(x) for x in self.declarations])
        if len(self.operations) > 0:
            output += "\n\n# Operations    :\n" + "\n".join([str(x) for x in self.operations])
        output += "\n\n# Rounds        :\n" + "\n".join([str(x) for x in self.rounds])
        return output

    def synthesize_c(self) -> str:
        output =  "#include<stdio.h>\n"
        output += "#include<stdlib.h>\n"
        output += "#include<math.h>\n"
        output += "#include<stdint.h>\n"
        output += "\n"
        output += "#define BIT(index) (1UL<<index)\n"
        output += "#define BITMASK(index) (BIT(index+1)-1)\n"
        output += "#define BIT_SELECT(word,index) ((word>>index) & 1)\n"
        output += "#define BITRANGE_BITMASK(msb,lsb) (BIT(msb+1)-BIT(lsb))\n"
        output += "#define BITRANGE_SELECT(word,msb,lsb) ((word & BITRANGE_BITMASK(msb,lsb))>>lsb)\n"
        output += "\n"
        output += "\n".join([declaration.synthesize_c() for declaration in self.declarations]) + "\n"
        output += "\n".join([operation.synthesize_c() for operation in self.operations]) + "\n"

        plaintext_length = self.input_length()
        ciphertext_length = self.rounds[-1].length() # Length of last round

        output += "void encrypt(uint64_t F0[" + str(plaintext_length) + \
                "], uint64_t ciphertext[" + str(ciphertext_length) + "]) {\n"
        output += "\tuint64_t " + \
                ", ".join([round.name + "[" + str(round.length()) + "] = {0}"
                           for round in self.rounds]) + ";\n\n"
        output += "\n".join([round.synthesize_c() for round in self.rounds]) + "\n"

        output += "\tprintf(\"\\nF0\\t\");\n"
        output += "\tfor (int i=0; i<" + str(plaintext_length) + "; i++)\n"
        output += "\t\tprintf(\"%02lx \", F0[i]);\n"

        for i, round in enumerate(self.rounds):
            output += "\tprintf(\"\\nF" + str(i+1) + "\\t\");\n"
            output += "\tfor (int i=0; i<" + str(round.length()) + "; i++)\n"
            output += "\t\tprintf(\"%02lx \", F" + str(i+1) + "[i]);\n"

        output += "\tfor (int i=0; i<" + str(ciphertext_length) + "; i++)\n"
        output += "\t\tciphertext[i] = F" + str(len(self.rounds)) + "[i];\n"
        output += "}\n\n"

        output += "int main() {\n"
        output += "\tuint64_t plaintext[" + str(plaintext_length) + "] = {" + \
                ", ".join([hex(x) for x in range(plaintext_length)]) + "};\n"
        output += "\tuint64_t ciphertext[" + str(ciphertext_length) + "];\n"
        output += "\tencrypt(plaintext, ciphertext);\n"
        output += "\tprintf(\"\\nFinal\\t\");\n"
        output += "\tfor (int i=0;i<" + str(ciphertext_length) + ";i++)\n"
        output += "\t\tprintf(\"%02lx \", ciphertext[i]);\n"
        output += "}"

        return output
