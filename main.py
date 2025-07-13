import sys
from cipherscore import CipherSpec

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <bcsl_file>")
        exit()
    cipher = CipherSpec(sys.argv[1])
    print(cipher)

if __name__ == "__main__":
    main()
