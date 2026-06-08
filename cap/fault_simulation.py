#################################################################################################
# This file contains functions to implement GDB-enabled fault simulation
#################################################################################################
import os
import re
import click
import random
import subprocess

annotation_definitions = """
#define FAULTINIT void __attribute__((optimize(0))) _fault_begin()  \\
    { printf("Beginning fault injection\\n"); }                      \\
    void __attribute__((optimize(0))) _fault_end()                  \\
    { printf("Finished fault injection\\n"); }

#define FAULTBEGIN _fault_begin();
#define FAULTEND   _fault_end();
#define FAULTOUTPUT(arr,len) {                                      \\
    printf("\\n>>>FAULTOUT ");                                       \\
    for (unsigned __faulti=0; __faulti<len; __faulti++)             \\
        printf("%lx ", arr[__faulti]);                              \\
    printf("\\n"); }

"""

def compile(file, workdir):
    """
    Check if the the file contains the require annotations and compile
    the annotated file for fault simulation
    """
    with open(file, 'r') as in_file:
        data = in_file.read()
        if ("FAULTINIT" not in data) or ("FAULTBEGIN" not in data) or \
                ("FAULTEND" not in data) or ("FAULTOUTPUT" not in data):
            click.echo(f"Error: File {file} does not contain all the required annotations (FAULTINIT, FAULTBEGIN, FAULTEND, FAULTOUTPUT)")
            exit()
        with open(os.path.join(workdir, "file.c"), "w+") as outfile:
            outfile.write(annotation_definitions)
            outfile.write(data)
    command = ["gcc", os.path.join(workdir,"file.c"), "-o", os.path.join(workdir,"bin")]
    process = subprocess.run(command)
    if process.returncode != 0:
        click.echo("Compilation with GCC failed. Exiting.")
        return


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
    # FIXME Need to run this in a container to prevent any accidental damage to system
    # FIXME Need to run in separate temporary folder so that gdb.txt file won't clash
    # FIXME Add a timeout
    if os.path.exists("gdb.txt"):
        os.remove("gdb.txt")
    binary          = os.path.join(workdir, "bin")
    scriptfilename  = os.path.join(workdir, scriptname)
    with open(scriptfilename, "w+") as scriptfile:
        scriptfile.write(gdbscript)
    process = subprocess.run(["gdb", "-x", scriptfilename, binary], capture_output=True)
    if process.returncode != 0:
        click.echo("Error running GDB")
        exit()
    with open("gdb.txt", "r") as logfile:
        log = logfile.read()
    return log, str(process.stdout)

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

all_possible_bitflip_masks = []

def fault_run(workdir, faults_per_byte, correct_output, addr_ranges):
    """
    Runs the annotated program with fault injection and stores the logs in the workdir
    """
    # First generate the gdbscript with the address and mask to corrupt
    for (startaddr, endaddr) in addr_ranges:
        for faultaddr in range(startaddr,endaddr+1,8):
            click.echo(">> Performing fault injection at " + str(hex(faultaddr)))
            for i in range(faults_per_byte):
                rand_index = random.randint(0,len(all_possible_bitflip_masks)-1)
                byte_mask = all_possible_bitflip_masks[rand_index]
                gdbscript = re.sub("ADDRESS", str(hex(faultaddr)), fault_gdbscript)
                gdbscript = re.sub("BYTEMASK", str(hex(byte_mask)), gdbscript)
                filename = "fault-" + str(hex(faultaddr)) + "-" + str(hex(byte_mask))
                log, output = run_gdb(filename+".gdb",
                                      gdbscript, workdir)
                with open(os.path.join(workdir, 
                                       filename+".log"),
                          "w") as outfile:
                    outfile.write(output)
                    outfile.write(log)

@click.command()
@click.argument("annotated-c-file")
@click.argument("workdir")
@click.option("--bitflips", "-b", default=3, help="Number of bit-flips to simulate (default:3)")
@click.option("--faults-per-byte", "-n", default=10, help="Number of faults per byte to simulate (default:10)")
def simulate_faults(annotated_c_file, workdir, bitflips, faults_per_byte):
    """
    - Simulates fault in cipher program based in the annotated region, 
      and outputs statistics on how many faults were successful for a 
      Differential Fault Attack on the Cipher.
    - Currently supports Instruction corruption faults based on a 
      N-bit flip model.
    - The logs are stored in the work directory specified, and can then
      be used to view statistics about the simulations
    
    Before running this command, you are expected to add the following 
    annotations to the cipher program
    1. FAULTINIT : Defines the FaultSim helper functions in the C program
    2. FAULTBEGIN, FAULTEND
        - Marks the beginning and end of the C program range where 
          we want to simulate faults
        - The FAULTBEGIN and FAULTEND should be called at the same function 
          call level, but can be called multiple times in the program
        - FaultSim iterates through every byte in the specified regions and 
          simulates faults in each of those bytes.
    3. FAULTOUTPUT(arrayname, len) : To mark the cipher output present in 
       the array named arrayname which is of length len.
    """
    os.makedirs(workdir, exist_ok=True)
    compile(annotated_c_file, workdir)
    correct_output, addr_ranges = oracle_run(workdir)
    with open(os.path.join(workdir,"correct_output"), "w") as correct_output_file:
        correct_output_file.write(correct_output)
    global all_possible_bitflip_masks
    all_possible_bitflip_masks = generate(8, bitflips, 0xff)
    fault_run(workdir, faults_per_byte, correct_output, addr_ranges)

@click.command()
@click.argument("workdir")
def show_fault_stats(workdir):
    """
    Show statistics for GDB-enabled fault simulation runs, based on the logs
    stored in the specified work directory.
    """
    total_simulations = 0
    terminated_with_signal = {}  # Dictionary of signal to count
    terminated_normally = [0, 0] # Correct / Incorrect output
    fault_effects = [] # List of tuples of form (original instruction, corrupted instruction)
    with open(os.path.join(workdir,"correct_output"), "r") as correct_output_file:
        correct_output = correct_output_file.read()
    for file in os.listdir(workdir):
        if file.endswith(".log"):
            total_simulations += 1
            with open(os.path.join(workdir,file), "r") as infile:
                data = infile.read()
                if "Terminated with Signal" in data:
                    # Terminated with signal
                    signal = ""
                    for line in data.split("\n"):
                        if line.startswith("Catchpoint") and \
                                line.split(" ")[2] == "(signal":
                            signal = line.split(" ")[3].split(")")[0]
                    assert signal != ""
                    if signal not in terminated_with_signal:
                        terminated_with_signal[signal] = 0
                    terminated_with_signal[signal] += 1
                elif ">>>FAULTOUT" in data:
                    # Terminated normally, Check output
                    if len(data.split(">>>FAULTOUT")) != 2:
                        click.echo("Error: Incorrect number of FAULTOUT entries. Expected one")
                        exit()
                    if data.split(">>>FAULTOUT")[1].split("\\n")[0] == \
                            correct_output.split(">>>FAULTOUT")[1]:
                        terminated_normally[0] += 1
                    else:
                        terminated_normally[1] += 1
                        orig_inst = data.split(">> Original instruction")[1].split("\\n")[0].split("\\t")[1]
                        mod_inst = data.split(">> Modified instruction")[1].split("\\n")[0].split("\\t")[1]
                        fault_effects.append((orig_inst,mod_inst))
                else:
                    total_simulations -= 1
    click.echo("{:30s} : {:10d}".format("Total simulations", total_simulations))
    click.echo("{:30s} : {:10d}".format("Terminated with signal",
                                        sum(terminated_with_signal.values())))
    for signal in terminated_with_signal:
        click.echo("\t- {:15s} : {:10d}".format(signal, terminated_with_signal[signal]))
    click.echo("{:30s} : {:10d}".format("Terminated normally",
                                        terminated_normally[0] + 
                                            terminated_normally[1]))
    click.echo("\t- {:15s} : {:10d}".format("Correct output", terminated_normally[0]))
    click.echo("\t- {:15s} : {:10d}".format("Changed output", terminated_normally[1]))
    click.echo("Fault instruction corruptions that changed output")
    for (orig_inst, mod_inst) in fault_effects:
        click.echo("\t {:30s} ==> {:30s}".format(orig_inst, mod_inst))
