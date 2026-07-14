#################################################################################################
# This file contains utility functions used across the application
#################################################################################################

import os
import subprocess
import click

def check_for_annotations(file, required_annotations_list):
    if len(required_annotations_list) == 0:
        return
    with open(file, 'r') as in_file:
        data = in_file.read()
        for required_annotation in required_annotations_list:
            if required_annotation not in data:
                click.echo(f"Error: File {file} does not contain the required annotation {required_annotation}")
                exit()

def compile_with_annotations(file, workdir, annotation_definitions, required_annotations_list=[]):
    """
    Check if the the file contains the require annotations and compile
    the annotated file for fault simulation

    Attributes:
        file (File)     : The input filename to compile with annotations
        workdir (str)   : The work directory to be used for writing temporary values
        annotation_definitions (str) : The #define string containing all the annotation definitions
        required_annotations_list (List(str)) : List of required annotations to check for in the program
    """
    check_for_annotations(file, required_annotations_list)
    with open(file, 'r') as in_file:
        data = in_file.read()
        with open(os.path.join(workdir, "file.c"), "w+") as outfile:
            outfile.write(annotation_definitions)
            outfile.write(data)
    command = ["gcc", os.path.join(workdir,"file.c"), "-o", os.path.join(workdir,"bin")]
    process = subprocess.run(command)
    if process.returncode != 0:
        click.echo("Compilation with GCC failed. Exiting.")
        return
