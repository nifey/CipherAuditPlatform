#! /usr/bin/env/python 3.1

import sys
import os
import argparse
import time

# add parent directory to search path so we can use py_common
sys.path.append("..")

import py_common

plugin = ''
include_dirs = ''
disabled_warnings = ' -Wno-incompatible-pointer-types '
sarif = False
explosion_factor = '5'

def run_scrub_analysis(c_file: str):
	"""
	This method is called from the run_analysis method.  It is called for
	each matching file.  Files are matched against the glob expression
	specified in main.

	When this method is called, the script will have changed to the directory 
	where the	batch file exists.
	"""
	
	# In order to run a source code analysis tool, build appropriate command
	# line(s) as shown in the commented out example below
	"""
	build_name = "toolname.c_and_cpp." + py_common.get_timestamp() + "." + bat_file[:-4]

	command1 = "mytool --build " + build_name + " --option1 --option2 " + bat_file

	py_common.print_with_timestamp("Running " + command1)
	py_common.run_commands([command1])

	command2 = "mytool --analyze " + build_name + " --output " + build_name + ".xml"

	py_common.print_with_timestamp("Running " + command2)
	py_common.run_commands([command2])
	"""

	omit_good = "-DOMITGOOD"
	omit_bad = "-DOMITBAD"

	global plugin
	global include_dirs
	global disabled_warnings
	global sarif
	global explosion_factor

	command = f"gcc -fplugin={plugin} -fanalyzer -c -o /dev/null "\
		+ include_dirs\
		+ disabled_warnings\
		+ f" {'-fdiagnostics-format=sarif-file' if sarif else ''} "\
		+ f" --param=analyzer-bb-explosion-factor={explosion_factor} "\
		+ f" {c_file}"
	
	py_common.print_with_timestamp(f'Running {command}')
	py_common.run_commands([command], True)

def run(args):
	wine_header_dir = '/usr/include/wine/wine/windows'
	if not os.path.exists(wine_header_dir):
		py_common.print_with_timestamp('Please install wine on your system.')
		exit()

	global plugin
	plugin = args.plugin
	if plugin is None:
		if 'PLUGIN' in os.environ:
			plugin = os.environ['PLUGIN']
		else:
			parser.print_usage()
			exit()

	if not os.path.isfile(plugin):
		py_common.print_with_timestamp(f'Plugin path issue (passed {plugin})')
		exit()

	interactive = args.interactive
	omit_bad = args.omit_bad
	omit_good = args.omit_good
	file = args.file
	root_dir = os.environ['PWD']

	global include_dirs
	include_dirs = f'-I{wine_header_dir} -I{root_dir}/testcasesupport'
	global sarif
	sarif = args.sarif
	global explosion_factor
	explosion_factor = args.explosion_factor

	py_common.print_with_timestamp(f'Plugin path: {plugin}')

	# Analyze the test cases
	# py_common.run_analysis("testcases", "CWE.*\\.bat", run_example_tool)

	if file is None:
		# Analyze the test cases for CWE-244
		py_common.print_with_timestamp(f"Running analysis on files regarding CWE-{args.cweid}")
		run_analysis("testcases", f"CWE{args.cweid}.*\\.c", run_scrub_analysis, interactive)
	else:
		py_common.print_with_timestamp(f"Running analysis on file {file}")
		py_common.run_analysis("testcases", file, run_scrub_analysis)

def run_analysis(test_case_path, build_file_regex, run_analysis_fx, interactive):

	# find all the files
	files = py_common.find_files_in_dir(test_case_path, build_file_regex)
	time_started = time.time()
	
	# run all the files using the function pointer
	for file in files:

		# change into directory with the file
		dir = os.path.dirname(file)
		os.chdir(dir)

		# run the the file
		file = os.path.basename(file)
		if interactive:
			py_common.print_with_timestamp(f'Run test \'{file}\'? default = yes, n/c = next test, e = exit, ')
			_input = input().lower()
			if _input.startswith('n') or _input.startswith('c'):
				continue
			elif _input.startswith('e'):
				exit(1)		
		run_analysis_fx(file)

		# return to original working directory
		os.chdir(sys.path[0])
	
	time_ended = time.time()

	py_common.print_with_timestamp("Started: " + time.ctime(time_started))
	py_common.print_with_timestamp("Ended: " + time.ctime(time_ended))

	elapsed_seconds = time_ended-time_started
	py_common.print_with_timestamp("Elapsed time: " + py_common.convertSecondsToDHMS(elapsed_seconds))


def list_cwe(args):
	py_common.run_analysis('testcases', f'CWE{args.cweid}.*\\.c', print)

if __name__ == '__main__':

	name = sys.argv[0]
	parser = argparse.ArgumentParser(
                    prog=f'{name}',
                    description='Run tests from Juliet testsuite')
	parser.add_argument('-d', '--debug',
										action='store_true')

	subparser = parser.add_subparsers (help='subcommands help')

	run_parser = subparser.add_parser('run',
										aliases=['r'],
										help='run tests or a specific test')
	run_parser.set_defaults(func=run)

	run_parser.add_argument('-p', '--plugin')
	run_parser.add_argument('-f', '--file')
	run_parser.add_argument('-s', '--sarif',
										action='store_true')
	run_parser.add_argument('-i', '--interactive',
                    action='store_true')
	run_parser.add_argument('--omit-good',
                    action='store_true')
	run_parser.add_argument('--omit-bad',
                    action='store_true')
	run_parser.add_argument('-id', '--cweid',
										choices=["244","226"],
										default="244",
										help='run tests for a specific CWE-ID [default: 244]')
	run_parser.add_argument('-e', '--explosion-factor',
										default='5',
										help='Modify the SA explosion factor [default: 5]')

	list_parser = subparser.add_parser('list',
										aliases=['l'],
										help='list tests')
	list_parser.set_defaults(func=list_cwe)

	list_parser.add_argument('-i', '--cweid',
										choices=["244","226"],
										default="244",
										help='list tests for a specific CWE-ID [default: 244]')

	args = parser.parse_args()

	if args.debug:
		print(args)

	if 'func' in args:
		args.func(args)
	else:
		parser.print_help()