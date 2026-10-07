import os
import re
import json
import tempfile
from flask import Flask, render_template, request
from cap import CipherSpec, cipher_parser
from cap.zeroization import run_gnuzero
from pyparsing import ParseException

template_folder_path = os.path.abspath("cap/templates")
static_folder_path = os.path.abspath("cap/static")
webapp = Flask("CAP WebUI",
               template_folder=template_folder_path,
               static_folder=static_folder_path)

@webapp.route("/")
def home():
    return render_template("index.html")

@webapp.route("/csl")
def csl():
    return render_template("csl.html")

@webapp.route("/runcsl", methods=["POST"])
def runcsl():
    data = {}
    try:
        cipher : CipherSpec = cipher_parser().parse_string(request.data.decode())[0]
        data['output'] = cipher.synthesize_c()
    except ParseException as e:
        data['error'] = "Parse error: " + str(e)
    return json.dumps(data)

@webapp.route("/zeroization")
def zeroization():
    return render_template("zeroization.html")

@webapp.route("/runzeroization", methods=["POST"])
def runzeroization():
    data = {}
    try:
        input_code : str = request.data.decode()
        with tempfile.NamedTemporaryFile() as infile:
            infile.file.write("#include \"scrub.h\"\n".encode())
            infile.file.write(input_code.encode())
            stdout, stderr = run_gnuzero(infile.name)
            if stderr == "":
                # Remove Bash ANSI error codes
                stdout = re.sub(r'\[K', '', stdout)
                stdout = re.sub(r'\[[^m]*m', '', stdout)
                data['output'] = re.sub(r'\[K', '', stdout)
            else:
                data['error'] = stderr
    except ParseException as e:
        data['error'] = "Parse error: " + str(e)
    return json.dumps(data)
