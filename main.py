import os
import click
from cap import CipherSpec, cipher_parser, fault_simulation
from cap import inbuilt_csls_files, inbuilt_csls_descriptions
from pyparsing import ParseException
from cap.zeroization import run_gnuzero
from cap.webui import webapp

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

@click.command()
@click.argument("annotated-c-file")
def check_zeroization(annotated_c_file):
    '''
       Uses GNUZero to check if there are any missed zeroization
    '''
    print(run_gnuzero(annotated_c_file)[0])

@click.command()
def serve():
    webapp.run(debug=True)
 
@click.group()
def cli():
    pass
cli.add_command(synthesize_csl)
cli.add_command(list_csl)
cli.add_command(fault_simulation.simulate_faults)
cli.add_command(check_zeroization)
cli.add_command(serve)

if __name__ == "__main__":
    cli()
