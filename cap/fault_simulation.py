#################################################################################################
# This file contains functions to implement GDB-enabled fault simulation
#################################################################################################
import os
import re
import json
import click
import random
import tempfile
import subprocess
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from .utils import has_required_annotations, compile_with_annotations

annotation_definitions = """
#define FAULT_INIT void __attribute__((optimize(0))) _fault_begin()  \\
    { printf("Beginning fault injection\\n"); }                      \\
    void __attribute__((optimize(0))) _fault_end()                  \\
    { printf("Finished fault injection\\n"); }

#define FAULT_BEGIN _fault_begin();
#define FAULT_END   _fault_end();
#define FAULT_OUTPUT(arr,len) {                                      \\
    printf("\\n>>>FAULTOUT ");                                       \\
    for (unsigned __faulti=0; __faulti<len; __faulti++)             \\
        printf("%lx ", arr[__faulti]);                              \\
    printf("\\n"); }

"""
init_gdbscript = """
set pagination off
set logging on
set confirm off

b _fault_begin
command
    printf ">>>Reached _fault_begin "
    frame level 1
    c
end

b _fault_end
command
    printf ">>>Reached _fault_end "
    frame level 1
    c
end

run
quit
"""

fault_gdbscript = """
set disassembly-flavor intel
set pagination off
set logging on
set confirm off

catch signal
command
    printf ">> Terminated with Signal\\n"
    quit
end

tb _fault_begin
command
    printf ">> Original instruction : "
    x/1i ADDRESS
    set $byte = ({char}ADDRESS) & 0xff
    set $newbyte = ($byte ^ BYTEMASK) & 0xff
    set {char}ADDRESS = $newbyte
    printf ">> Changed %x to %x at ADDRESS\\n", $byte, $newbyte
    printf ">> Modified instruction : "
    x/1i ADDRESS
    c
end

run
quit
"""

def run_gdb(scriptname, gdbscript, workdir):
    if os.path.exists("gdb.txt"):
        os.remove("gdb.txt")
    binary          = os.path.abspath(os.path.join(workdir, "bin"))
    with tempfile.TemporaryDirectory() as tempdir:
        with open(os.path.join(tempdir, scriptname), "w+") as scriptfile:
            scriptfile.write(gdbscript)
        try:
            process = subprocess.run(["gdb", "-x", scriptname, binary],
                                     capture_output=True,
                                     cwd=tempdir, timeout=5)
            if process.returncode != 0:
                click.echo("Error running GDB")
                exit()
            with open(os.path.join(tempdir, "gdb.txt"), "r") as logfile:
                log = logfile.read()
            return log, str(process.stdout)
        except subprocess.TimeoutExpired:
            with open(os.path.join(tempdir, "gdb.txt"), "r") as logfile:
                log = logfile.read()
            return log, "TIMEOUT REACHED"

def oracle_run(workdir):
    """
    Runs the annotated program without fault injection to get the fault address ranges
    """
    log, output = run_gdb("init.gdb", init_gdbscript, workdir)
    if len(output.split(">>>FAULTOUT")) != 2:
        click.echo("Error: Only one FAULTOUT was expected in the output")
    correct_output = ""
    for line in output.split("\\n"):
        if line.startswith(">>>FAULTOUT"):
            correct_output = line
            break
    addr_ranges = []
    trace = []
    for line in log.split("\n"):
        if line.startswith(">>>Reached"):
            words = line.split(" ")
            trace.append((words[1], words[4]))
    for i in range(int(len(trace)/2)):
        if trace[i*2][0] != "_fault_begin":
            click.echo("Error: _fault_begin should be first in the trace")
            exit()
        if trace[i*2+1][0] != "_fault_end":
            click.echo("Error: _fault_end should follow _fault_begin in the trace")
            exit()
        addr_ranges.append((int(trace[i*2][1], 16), int(trace[i*2+1][1], 16)))
    return correct_output, addr_ranges


def recursive_generate(bitstring_length, n, mask,
                       current_reverse_string, current_pos, generated_list):
    if current_pos == bitstring_length:
        # Finished generating one full bitstring, save it
        generated_list.append(int("".join([str(x) for x in current_reverse_string]), 2))
    else:
        current_reverse_string[current_pos] = 0
        recursive_generate(bitstring_length, n, mask,
                                          current_reverse_string,
                                          current_pos + 1, generated_list)
        if ((mask >> (bitstring_length - current_pos - 1)) & 1 == 1) and n > 0:
            # If the current_pos has to be considered for setting,
            # and we haven't already set the required bits
            current_reverse_string[current_pos] = 1
            recursive_generate(bitstring_length, n - 1, mask,
                                              current_reverse_string,
                                              current_pos + 1, generated_list)
def generate(bitstring_length, n, mask):
    """
    Enumerates all possible bitstrings with maximum n number of 1's in it, 
    filled at the bit positions specified by the mask argument
    """
    generated_list = []
    recursive_generate(bitstring_length, n, mask,
                                      [0 for x in range(bitstring_length)],
                                      0, generated_list)
    return generated_list

all_possible_bitflip_masks = {}

def one_fault_run(faultaddr, byte_mask, workdir):
    # Generate the gdbscript with the address and mask to corrupt
    gdbscript = re.sub("ADDRESS", str(hex(faultaddr)), fault_gdbscript)
    gdbscript = re.sub("BYTEMASK", str(hex(byte_mask)), gdbscript)
    filename = "fault-" + str(hex(faultaddr)) + "-" + str(hex(byte_mask))
    log, output = run_gdb(filename+".gdb", gdbscript, workdir)
    with open(os.path.join(workdir, filename+".log"), "w") as outfile:
        outfile.write(output)
        outfile.write(log)

def run_fault_simulation(annotated_c_file, bitflips, faults_per_byte):
    """
    Runs the annotated program with fault injection and stores the logs in the workdir
    """
    if bitflips <= 0 or bitflips > 8:
        return ("", "Error: Invalid bitflip value specified")
    if faults_per_byte <= 0:
        return ("", "Error: Invalid faults per byte value specified")
    workdir = tempfile.TemporaryDirectory().name
    os.mkdir(workdir)
    if not has_required_annotations(annotated_c_file,
                                    ["FAULT_INIT", "FAULT_BEGIN", "FAULT_END", "FAULT_OUTPUT"]):
        return ("", "Error: File does not contain all required annotations")
    compile_with_annotations(annotated_c_file, workdir, annotation_definitions,
                         ["FAULT_INIT", "FAULT_BEGIN", "FAULT_END", "FAULT_OUTPUT"])
    correct_output, addr_ranges = oracle_run(workdir)
    with open(os.path.join(workdir,"correct_output"), "w") as correct_output_file:
        correct_output_file.write(correct_output)
    global all_possible_bitflip_masks
    if bitflips not in all_possible_bitflip_masks:
        all_possible_bitflip_masks[bitflips] = generate(8, bitflips, 0xff)
    faults = []
    for (startaddr, endaddr) in addr_ranges:
        for faultaddr in range(startaddr,endaddr+1):
            for i in range(faults_per_byte):
                rand_index = random.randint(0,len(all_possible_bitflip_masks[bitflips])-1)
                byte_mask = all_possible_bitflip_masks[bitflips][rand_index]
                faults.append((faultaddr, byte_mask))
    with ThreadPoolExecutor() as executor:
        list(tqdm(executor.map(lambda x: one_fault_run(x[0], x[1], workdir), faults),
                  total=len(faults), desc="Simulating faults in the annotated region",
                  colour='Blue'))
    return (workdir, "")

def get_fault_stats(workdir):
    total_simulations = 0
    termination_reason = {}
    termination_reason["timeout"] = 0
    termination_reason["normal-correct"] = 0
    termination_reason["normal-incorrect"] = 0
    fault_effects = [] # List of tuples of form (original instruction, corrupted instruction)
    errors = []
    with open(os.path.join(workdir,"correct_output"), "r") as correct_output_file:
        correct_output = correct_output_file.read()
    for file in os.listdir(workdir):
        if file.endswith(".log"):
            total_simulations += 1
            with open(os.path.join(workdir,file), "r") as infile:
                data = infile.read()
                if "Terminated with Signal" in data:
                    signal = ""
                    for line in data.split("\n"):
                        if line.startswith("Catchpoint") and \
                                line.split(" ")[2] == "(signal":
                            signal = line.split(" ")[3].split(")")[0]
                    assert signal != ""
                    if signal not in termination_reason:
                        termination_reason[signal] = 0
                    termination_reason[signal] += 1
                elif "received signal SIGTRAP" in data:
                    if "SIGTRAP" not in termination_reason:
                        termination_reason["SIGTRAP"] = 0
                    termination_reason["SIGTRAP"] += 1
                elif ">>>FAULTOUT" in data:
                    # Terminated normally, Check output
                    if len(data.split(">>>FAULTOUT")) != 2:
                        errors.append("Error: Incorrect number of FAULTOUT entries in " + file)
                        continue
                    if data.split(">>>FAULTOUT")[1].split("\\n")[0] == \
                            correct_output.split(">>>FAULTOUT")[1]:
                        termination_reason["normal-correct"] += 1
                    else:
                        termination_reason["normal-incorrect"] += 1
                        orig_inst = data.split(">> Original instruction")[1].split("\\n")[0].split("\\t")[1]
                        mod_inst = data.split(">> Modified instruction")[1].split("\\n")[0].split("\\t")[1]
                        fault_effects.append((orig_inst,mod_inst))
                elif "TIMEOUT REACHED" in data:
                    termination_reason["timeout"] += 1
                else:
                    errors.append(f"{file} is not matching any termination pattern")
                    total_simulations -= 1
    fault_stats = {}
    fault_stats["total_simulations"] = total_simulations
    fault_stats["termination_reason"] = termination_reason
    fault_stats["fault_effects"] = fault_effects
    fault_stats["errors"] = errors
    return fault_stats

@click.command()
@click.argument("annotated-c-file")
@click.option("--bitflips", "-b", default=3, help="Number of bit-flips to simulate (default:3)")
@click.option("--faults-per-byte", "-n", default=10, help="Number of faults per byte to simulate (default:10)")
def simulate_faults(annotated_c_file, bitflips, faults_per_byte):
    """
    - Simulates fault in cipher program based in the annotated region, 
      and outputs statistics on how many faults were successful for a 
      Differential Fault Attack on the Cipher.
    - Currently supports Instruction corruption faults based on a 
      N-bit flip model.
    
    Before running this command, you are expected to add the following 
    annotations to the cipher program
    1. FAULT_INIT : Defines the FaultSim helper functions in the C program
    2. FAULT_BEGIN, FAULT_END
        - Marks the beginning and end of the C program range where 
          we want to simulate faults
        - The FAULT_BEGIN and FAULT_END should be called at the same function 
          call level, but can be called multiple times in the program
        - FaultSim iterates through every byte in the specified regions and 
          simulates faults in each of those bytes.
    3. FAULT_OUTPUT(arrayname, len) : To mark the cipher output present in 
       the array named arrayname which is of length len.
    """
    workdir, error = run_fault_simulation(annotated_c_file, bitflips, faults_per_byte)
    if error != "":
        click.echo(error)
        exit(1)
    click.echo("{:30s} : {:20s}".format("Work directory", workdir))
    fault_stats = get_fault_stats(workdir)

    # Dump the statistics to output file
    with open("fault_simulation_output.json", "w+") as dumpfile:
        json.dump(fault_stats, dumpfile, indent=4)

    # Print the statistics in the terminal
    click.echo("{:30s} : {:10d}".format("Total simulations", fault_stats["total_simulations"]))
    termination_reason = fault_stats["termination_reason"]
    click.echo("{:30s} : {:10d}".format("Terminated with timeout", termination_reason["timeout"]))
    terminated_with_signal = 0
    for signal in termination_reason:
        if signal.startswith("SIG"):
            terminated_with_signal += termination_reason[signal]
    click.echo("{:30s} : {:10d}".format("Terminated with signal", terminated_with_signal))
    for signal in termination_reason:
        if signal.startswith("SIG"):
            click.echo("\t- {:15s} : {:10d}".format(signal, termination_reason[signal]))
    click.echo("{:30s} : {:10d}".format("Terminated normally",
                                        termination_reason["normal-correct"] + 
                                            termination_reason["normal-incorrect"]))
    click.echo("\t- {:15s} : {:10d}".format("Correct output", termination_reason["normal-correct"]))
    click.echo("\t- {:15s} : {:10d}".format("Changed output", termination_reason["normal-incorrect"]))
    click.echo("Fault instruction corruptions that changed output")
    for (orig_inst, mod_inst) in fault_stats["fault_effects"]:
        click.echo("\t {:30s} ==> {:30s}".format(orig_inst, mod_inst))
