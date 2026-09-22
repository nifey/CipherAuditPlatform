import os
import json
from flask import Flask, render_template, request
from cap import CipherSpec, cipher_parser
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

@webapp.route("/runcap", methods=["POST"])
def runcap():
    data = {}
    try:
        cipher : CipherSpec = cipher_parser().parse_string(request.data.decode())[0]
        data['output'] = cipher.synthesize_c()
    except ParseException as e:
        data['error'] = "Parse error: " + str(e)
    return json.dumps(data)
