import os
import click
import shutil
import tempfile
import subprocess
from cap import CipherSpec, cipher_parser, fault_simulation
from pyparsing import ParseException
from cap.utils import check_for_annotations

inbuilt_csls_files = {
    "AES-128"       : "AES_128.csl",
    "CLEFIA-128"    : "CLEFIA_128.csl",
    "SPECK-128"     : "SPECK_128.csl",
    "PRESENT-80"    : "PRESENT_80.csl",
    "ASCON-128"     : "ASCON128.csl",
    "CHACHA-20"     : "CHACHA20.csl",
    "TRIVIUM"       : "Trivium.csl",
        }

inbuilt_csls_descriptions = {
    "AES-128"       : "AES block cipher with 128 bit keys",
    "CLEFIA-128"    : "CLEFIA block cipher with 128 bit keys",
    "SPECK-128"     : "SPECK block cipher with 128 bit keys",
    "PRESENT-80"    : "PRESENT lightweight block cipher with 80 bit keys",
    "ASCON-128"     : "ASCON stream cipher with 128 bit keys",
    "CHACHA-20"     : "CHACHA20 stream cipher",
    "TRIVIUM"       : "TRIVIUM stream cipher",
        }

@click.command()
@click.option('--show', '-s', default="", help='Name of CSL to show')
def list_csl(show):
    '''\b
        List the inbuilt cipher specifications available. If a specific inbuilt 
        specification is specified as an argument to the --show / -s flag, then 
        the CSL file is printed as output.
    '''
    if show == "":
        # No specific CSL specified, so list inbuilt CSLs
        click.echo("List of inbuilt CSL specifications available")
        for csl in inbuilt_csls_descriptions:
            description = inbuilt_csls_descriptions[csl]
            click.echo("> {:20s} : {:s}".format(csl, description))
    else:
        show = show.upper()
        if show not in inbuilt_csls_files:
            click.echo(f"Cipher {show} in not found in the inbuilt specifications")
            return
        with open("specifications/" + inbuilt_csls_files[show], 'r') as csl_file:
            print("".join(csl_file.readlines()))

@click.command()
@click.argument("cslfile")
def synthesize_csl(cslfile):
    '''\b
       Synthesize cipher specification file in CSL format (or an inbuilt 
        CSL specification) into a golden reference C implementation.
    '''
    if cslfile.upper() in inbuilt_csls_files:
        cslfile = "specifications/" + inbuilt_csls_files[cslfile.upper()]
    try:
        with open(cslfile, "r") as infile:
            data = infile.read()
    except IOError as e:
        click.echo(f"Error opening CSL file : {cslfile}")
        return
    try:
        cipher : CipherSpec = cipher_parser().parse_string(data)[0]
        print(cipher.synthesize_c())
    except ParseException as e:
        click.echo("Parse error: ", end="")
        click.echo(e)
        exit()

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

@click.command()
@click.argument("annotated-c-file")
def check_zeroization(annotated_c_file):
    '''
       Uses GNUZero to check if there are any missed zeroization
    '''
    check_for_annotations(annotated_c_file, ["SCRUB_ATTR"])
    pull_zeroization_docker_image()

    file_parts = annotated_c_file.split(os.path.sep)
    if len(file_parts) == 1:
        parent_directory="."
        filename = file_parts[0]
    else:
        parent_directory=os.path.sep.join(file_parts[:-1])
        filename = file_parts[-1]
    with tempfile.TemporaryDirectory() as tempdir:
        shutil.copytree(parent_directory, tempdir, dirs_exist_ok=True)
        os.system(f"docker run --rm -v \"{tempdir}:/output\" -t ankitacool/gnuzero:latest gcc -I/opt/CipherAuditPlatform/zeroisation/gnuzero -fanalyzer -fplugin=/opt/CipherAuditPlatform/zeroisation/gnuzero/build_custom/libscrub.so -c /output/{filename}")

@click.group()
def cli():
    pass
cli.add_command(synthesize_csl)
cli.add_command(list_csl)
cli.add_command(fault_simulation.simulate_faults)
cli.add_command(fault_simulation.show_fault_stats)
cli.add_command(check_zeroization)

if __name__ == "__main__":
    cli()
