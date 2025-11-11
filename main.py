import sys
from cap import CipherSpec, cipher_parser
from pyparsing import ParseException

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <csl_file>")
        exit()
    data : str = ""
    with open(sys.argv[1], "r") as infile:
        data = infile.read()
    try:
        cipher : CipherSpec = cipher_parser().parseString(data)[0]
        print(cipher.synthesize_c())
    except ParseException as e:
        print("Parse error: ", end="")
        print(e)
        exit()

if __name__ == "__main__":
    main()
