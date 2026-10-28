import os
import shutil
import tempfile
import subprocess
from cap.utils import has_required_annotations

def pull_zeroization_docker_image():
    process = subprocess.run(["docker", "image", "ls"], capture_output=True, text=True)
    if process.returncode != 0:
        click.echo("Command 'docker image ls' failed. Check if you have installed docker correctly")
        exit()
    if "ankitacool/gnuzero:latest" not in process.stdout:
        # Docker image not present. Pull from Docker hub
        process = subprocess.run(["docker", "pull", "ankitacool/gnuzero:latest"])
        if process.returncode != 0:
            click.echo("Docker pull of GNUZero image failed")
            exit()
        click.echo("Successfully pulled the docker image for zeroization")

def run_gnuzero(annotated_c_file):
    pull_zeroization_docker_image()
    contains_annotation, missed_annotation = has_required_annotations(
            annotated_c_file, ["SCRUB_ATTR"])
    if not contains_annotation:
        return ("", "Error: File does not contain the required annotation " + missed_annotation)
    file_parts = annotated_c_file.split(os.path.sep)
    if len(file_parts) == 1:
        parent_directory = "."
        filename = file_parts[0]
    else:
        parent_directory = os.path.sep.join(file_parts[:-1])
        filename = file_parts[-1]
    with tempfile.TemporaryDirectory() as tempdir:
        # Add the include file to the input file
        with open(os.path.join(tempdir, filename + ".c"), "w+") as inputfile:
            with open(annotated_c_file, 'r') as annofile:
                inputfile.write("#include \"scrub.h\"\n")
                inputfile.write(annofile.read())
        command = "docker run --rm -v " + tempdir + ":/output -t ankitacool/gnuzero:latest gcc -I/opt/CipherAuditPlatform/zeroisation/gnuzero -fanalyzer -fplugin=/opt/CipherAuditPlatform/zeroisation/gnuzero/build_custom/libscrub.so -c /output/" + filename + ".c"
        output = subprocess.run(command, shell=True, capture_output=True)
        return (output.stdout.decode(), output.stderr.decode())
