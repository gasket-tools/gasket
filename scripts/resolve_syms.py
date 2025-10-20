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

EXCLUDE_LIBS = []

GDB_PYTHON_SCRIPT_HEADER = """
import gdb

def addr2symbol(address):
    try:
        gdb_address = gdb.parse_and_eval(f'({address})')

        # Use GDB's `info symbol` to get the symbol at the address
        symbol_info = gdb.execute(f'info symbol {gdb_address}', to_string=True).strip()

        if symbol_info:
            print(f'___ADDRESS___{address}___ADDRESS______FUNC___{symbol_info}___FUNC___')
        else:
            print(f'___ADDRESS___{address}___ADDRESS______FUNC___NOTFOUND___FUNC___')
    except gdb.error as e:
        print(f'___ADDRESS___{address}___ADDRESS______ERROR___{e}___ERROR___')
"""

# XXX: VERY important as automatic demangling causes the
#      REGEX in parse_gdb_line() to fail.
GDB_NO_DEMANGLE_INVOKE = "gdb.execute('set print demangle off')\n"
GDB_ADDR2SYMBOL_INVOKE = "addr2symbol(%s)\n"
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
    p = argparse.ArgumentParser(description='Resolve addresses to symbols using GDB')
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
        help=("PID of the process to attach to"),
    )
    p.add_argument(
        "-o",
        "--output",
        default=None,
        help=("Output file. Example --output resolved.json"),
    )
    p.add_argument(
        "-i",
        "--input",
        default=None,
        help=("Absolute path to the input file."),
    )

    return p.parse_args()

def run_gdb(symbol_addresses, target_pid):
    # XXX: The .py suffix is very important, as GDB uses it to
    #      decide how to interpret the sourced file.
    with tempfile.NamedTemporaryFile(suffix=".py", mode='w') as cmd_file:
        cmd_file_path = cmd_file.name
        script = GDB_PYTHON_SCRIPT_HEADER
        script += GDB_NO_DEMANGLE_INVOKE
        for addr in symbol_addresses:
            script += GDB_ADDR2SYMBOL_INVOKE % addr
        script += GDB_QUIT_INVOKE

        cmd_file.write(script)
        cmd_file.flush()

        # print("script = %s" % script)

        # XXX: Need sudo, because otherwise can't trace process.
        gdb_launch_cmd = f'sudo gdb --batch -ex "source {cmd_file_path}" --pid {target_pid}'
        # print("LAUNCH_CMD = %s" % gdb_launch_cmd)

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
        # log.info(f"STDOUT = {stdout}")
        # log.info(f"STDERR = {stderr}")
        fout.close()
        ferr.close()
        try:
            os.remove(fout.name)
            os.remove(ferr.name)
        except Exception as e:
            log.warning(e)
        return stdout

def parse_gdb_line(line):
    ret = None

    notfound_pattern = r"___ADDRESS___(.*?)___ADDRESS______FUNC___NOTFOUND___FUNC___"
    match = re.search(notfound_pattern, line)

    if match:
        address = match.group(1)
        log.debug("Address: %s | NOTFOUND" % address)
        return ret

    pattern = r"___ADDRESS___(.*?)___ADDRESS______FUNC___(\S+)\s+in section\s+(\S+)\s+of\s+(.+)___FUNC___"
    match = re.search(pattern, line)

    if match:
        address = match.group(1)
        # c_auxinfo = match.group(2)
        c_name = match.group(2)
        section = match.group(3)
        library = match.group(4)
        log.debug("Address: %s" % address)
        log.debug("C Name: %s" % c_name)
        log.debug("Library: %s" % library)

        ret = objects.PyCHop(None, address, c_name, section, library)
    else:
        log.debug(f"Could not match pat for line: {line}")

    return ret

class Analyzer():
    def __init__(self, input_file, target_pid, output_file):
        self.input_file = input_file
        self.output_file = output_file
        self.target_pid = target_pid
        self.symbol_addresses = []
        self.resolved = {}
        self.hops = []
    def process(self):
        with open(self.input_file, 'r') as infile:
            self.symbol_addresses = json.loads(infile.read())
        log.debug(f'ADDRESSES = {self.symbol_addresses}')
        log.debug('Running GDB')
        gdb_output = run_gdb(self.symbol_addresses, self.target_pid)
        for line in gdb_output.splitlines():
            hop = parse_gdb_line(line)
            if hop is not None:
                self.hops.append(hop)
        if (len(self.symbol_addresses) != len(self.hops)):
            log.debug(("len(symbol_addresses) = %s != %s = len(hops)"
                   % (len(self.symbol_addresses), len(self.hops))))
        else:
            log.debug("len(hops) = %s" % len(self.hops))

        bridges = []

        for h in self.hops:
            address = hex(h.address)
            lib = h.library
            cfunc = h.cfunc
            d = {'cfunc': cfunc, 'library': lib}
            self.resolved[address] = d


        if self.output_file is None:
            log.info(json.dumps(self.resolved, indent=2))
        else:
            with open(self.output_file, 'w') as outfile:
                outfile.write(json.dumps(self.resolved, indent=2))

def main():
    args = parse_args()
    setup_logging(args)
    if args.input is None:
        log.error("Must give input file path")
        sys.exit(1)
    json_path = args.input
    if not os.path.exists(json_path):
        log.error(f"Input file {json_path} does not exist")
        sys.exit(1)
    analyzer = Analyzer(args.input, args.pid, args.output)
    analyzer.process()

if __name__ == "__main__":
    main()
