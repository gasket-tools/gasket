import os
import re
import sys
import logging
import argparse
import json

import subprocess
import tempfile

from pathlib import Path

import objects

log = logging.getLogger(__name__)

# EXCLUDE_LIBS = [str(Path(sys.executable).resolve())]
EXCLUDE_LIBS = []

GDB_PYTHON_SCRIPT = """
import gdb

loaded_libs = gdb.execute('info sharedlibrary', to_string=True).strip()
print(loaded_libs)
"""

GDB_QUIT_INVOKE = "gdb.execute('quit')\n"

def setup_logging(args):
    levels = {
        "critical": logging.CRITICAL,
        "error": logging.ERROR,
        "warn": logging.WARNING,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG,
    }
    level = levels.get(args.log.lower())
    if level is None:
        raise ValueError(
            f"log level given: {args.log}"
            f" -- must be one of: {' | '.join(levels.keys())}"
        )

    fmt = "%(asctime)s "
    fmt += "%(module)s:%(lineno)s [%(levelname)s] "
    fmt += "%(message)s"
    # Use ISO 8601 format
    datefmt='%Y-%m-%dT%H:%M:%S'

    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)

def parse_args():
    p = argparse.ArgumentParser(description='Get a list of loaded shared libraries using GDB.')
    p.add_argument(
        "-l",
        "--log",
        default="info",
        help=("Provide logging level. Example --log debug"),
    )
    p.add_argument(
        "-p",
        "--pid",
        default=None,
        help=("PID of the process to trace."),
    )
    p.add_argument(
        "-o",
        "--output",
        default=None,
        help=("Output file. Example --output loaded_libs.json"),
    )
    return p.parse_args()

def run_gdb(target_pid):
    # XXX: The .py suffix is very important, as GDB uses it to
    #      decide how to interpret the sourced file.
    with tempfile.NamedTemporaryFile(suffix=".py", mode='w') as cmd_file:
        cmd_file_path = cmd_file.name
        script = GDB_PYTHON_SCRIPT
        script += GDB_QUIT_INVOKE

        cmd_file.write(script)
        cmd_file.flush()

        print("script = %s" % script)

        # XXX: Need sudo, because otherwise can't trace process.
        gdb_launch_cmd = f'sudo gdb --batch -ex "source {cmd_file_path}" --pid {target_pid}'

        try:
            fout = tempfile.NamedTemporaryFile(delete=False)
            ferr = tempfile.NamedTemporaryFile(delete=False)
            p = subprocess.run(
                gdb_launch_cmd,
                shell=True,  # Run the command through the shell
                stdout=fout,
                stderr=ferr,
                text=True,  # Return output as a string (available in Python 3.7+)
            )
        except subprocess.CalledProcessError as e:
            print("subprocess run failed: %s" % e)
            raise
        fout.close()
        ferr.close()
        fout = open(fout.name, 'r')
        ferr = open(ferr.name, 'r')
        stdout = fout.read()
        stderr = ferr.read()
        log.debug(fout.name)
        log.debug(ferr.name)
        log.info(f"STDOUT = {stdout}")
        log.info(f"STDERR = {stderr}")
        fout.close()
        ferr.close()
        try:
            os.remove(fout.name)
            os.remove(ferr.name)
        except Exception as e:
            log.warning(e)
        return stdout

class Analyzer():
    def __init__(self,target_pid, output_file):
        self.output_file = output_file
        self.target_pid = target_pid
        self.libs = []
    def process(self):
        gdb_output = run_gdb(self.target_pid)
        log.info('GDB RETURN STRING')
        log.info(gdb_output)
        self.libs = re.findall(r"/[^\s]+\.so(?:\.\d+)*", gdb_output)
        if self.output_file is None:
            log.info(json.dumps(self.libs, indent=2))
        else:
            with open(self.output_file, 'w') as outfile:
                outfile.write(json.dumps(self.libs, indent=2))

def main():
    args = parse_args()
    setup_logging(args)
    analyzer = Analyzer(args.pid, args.output)
    analyzer.process()

if __name__ == "__main__":
    main()
