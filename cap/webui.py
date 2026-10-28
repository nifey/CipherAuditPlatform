import os
import re
import json
import tempfile
from flask import Flask, render_template, request
from cap import CipherSpec, cipher_parser
from cap import inbuilt_csls_files, inbuilt_csls_descriptions
from cap.zeroization import run_gnuzero
from cap.fault_simulation import run_fault_simulation, get_fault_stats
from pyparsing import ParseException

template_folder_path = os.path.abspath("cap/templates")
static_folder_path = os.path.abspath("cap/static")
webapp = Flask("CAP WebUI",
               template_folder=template_folder_path,
               static_folder=static_folder_path)

@webapp.route("/")
def home():
    return render_template("index.html")

@webapp.route("/inbuiltcsl", methods=["POST"])
def inbuilt_csl():
    data = {}
    try:
        requestJSON = json.loads(request.data.decode())
        cslfile : str = requestJSON["inbuiltcsl"]
        if cslfile.upper() not in inbuilt_csls_files:
            data['error'] = "Invalide CSL file provided"
        else:
            cslfile = "specifications/" + inbuilt_csls_files[cslfile.upper()]
            with open(cslfile, "r") as infile:
                data['output'] = infile.read()
    except ParseException as e:
        data['error'] = "Error loading CSL file"
    return json.dumps(data)

@webapp.route("/csl")
def csl():
    return render_template("csl.html", inbuilt_csls=inbuilt_csls_descriptions)

@webapp.route("/runcsl", methods=["POST"])
def runcsl():
    data = {}
    try:
        requestJSON = json.loads(request.data.decode())
        cipher : CipherSpec = cipher_parser().parse_string(requestJSON["fileContents"])[0]
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
        requestJSON = json.loads(request.data.decode())
        input_code : str = requestJSON["fileContents"]
        if isinstance(input_code, (bytes, bytearray)):
            input_code = input_code.decode()
        with tempfile.NamedTemporaryFile(mode="w+",delete=False) as infile:
            infile.file.write(input_code)
            infile.file.close()
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

@webapp.route("/faultsimulation")
def fault_simulation():
    return render_template("faultsimulation.html")

@webapp.route("/runfaultsimulation", methods=["POST"])
def runfaultsimulation():
    data = {}
    try:
        requestJSON = json.loads(request.data.decode())
        input_code : str = requestJSON["fileContents"]
        bitflips : int = int(requestJSON["bitflips"])
        faultsPerByte : int = int(requestJSON["faultsPerByte"])
        with tempfile.NamedTemporaryFile() as infile:
            infile.file.write(input_code.encode())
            infile.file.close()
            workdir, error = run_fault_simulation(infile.name, bitflips, faultsPerByte)
            if error != "":
                data['error'] = error
            else:
                data['output'] = json.dumps(get_fault_stats(workdir))
    except ParseException as e:
        data['error'] = "Parse error: " + str(e)
    return json.dumps(data)
