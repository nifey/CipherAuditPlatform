# Cipher Audit Platform (CAP)

Tool for auditing Block Cipher implementations for points vulnerable to fault injection attacks, and to also quantize the exploitability.

Block cipher algorithms have to be specified in Cipher Specification Language (CSL). Some resources to get started writing Cipher Specifications:
- [specifications/AES\_128.csl](specifications/AES_128.csl) contains the specification of AES-128 Block cipher in CSL. Note that the Key Expansion is not yet implemented.
- [cap/cipherspec.py](cap/cipherspec.py) contains the complete grammar of Cipher Specification Language.

## Installation and Usage
```sh
# Create a python virtual environment
python -m venv env
source env/bin/activate

# Install dependencies using pip
pip install -e .

# Run CAP
python main.py <csl-file>
```
