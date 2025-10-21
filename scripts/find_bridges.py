#!/usr/bin/env python3
import os
import re
import sys
import json
import argparse
import logging
from pathlib import Path
import shutil
import multiprocessing
import concurrent.futures
import tempfile

import utils

log = logging.getLogger(__name__)

GASKET_ROOT = os.getenv("GASKET_ROOT")
GASKET = os.path.join(GASKET_ROOT, 'bin/gasket.js')

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
    p = argparse.ArgumentParser(description='Use Gasket to generate bridges for a set of Node.js packages.')
    p.add_argument(
        "-l",
        "--log",
        default="info",
        help=("Provide logging level. Example --log debug"),
    )
    p.add_argument(
        "-i",
        "--input",
        default=None,
        help=("Path to a CSV file with package:version pairs."),
    )
    p.add_argument(
        "-A",
        "--always",
        default=False,
        action='store_true',
        help=("Always generate artifacts; do not reuse existing data (e.g., installs)."),
    )
    return p.parse_args()

class JavascriptBridger():
    def __init__(self, package, always):
        self.always = always
        self.package = package
        self.stripped = False
        self.sanitized_package = utils.sanitize_package_name(self.package)
        if ':' not in package:
            log.error(f'{package} does not include a version delimiter ":"')
        self.name = package.split(':')[0]
        self.sname = self.sanitized_package.split(':')[0]
        self.version = package.split(':')[1]
        self.sversion = self.sanitized_package.split(':')[1]


        self.jsname_stripped = set()


        self.n2cgpath = None

        self.namesnip = self.name[0] + '/' + self.sname + '/' + self.sversion

        self.tempinst_uuid = self.sname + '___' + self.sversion
        self.tmp_install_dir_root = os.path.join(GASKET_ROOT, 'data/install')
        self.tmp_install_dir = os.path.join(self.tmp_install_dir_root, self.tempinst_uuid)

        self.pkg_inner_dir = os.path.join(self.tmp_install_dir, 'node_modules', self.name)

        self.bridges_root = os.path.join(GASKET_ROOT, 'data/bridges')
        self.bridges_apps_root = os.path.join(GASKET_ROOT, 'data/bridges/npm')
        self.bridges_dir = os.path.join(self.bridges_apps_root, self.namesnip)
        self.bridges_path = os.path.join(self.bridges_dir, 'bridges.json')

        self.bridges_csv_dir = os.path.join(GASKET_ROOT, 'data/gasket_bridges')
        utils.create_dir(self.bridges_csv_dir)
        self.bridges_csv_path = os.path.join(self.bridges_csv_dir, self.sname + '.txt')

        utils.create_dir(os.path.join(self.bridges_apps_root, self.namesnip))

    def install_package(self):
        log.info(f"Installing {self.package}")
        if os.path.exists(self.tmp_install_dir) and not self.always:
            log.info(f"Temp install dir for {self.package} already exists at {self.tmp_install_dir} - Skipping...")
            log.info(f"Use -A to force recreation.")
            return 0
        else:
            if os.path.exists(self.tmp_install_dir):
                shutil.rmtree(self.tmp_install_dir)
            utils.create_dir(self.tmp_install_dir)
            cmd = [
                'npm',
                'install',
                '--prefix', self.tmp_install_dir,
                "{}@{}".format(self.name, self.version)
            ]
            log.info(cmd)
            try:
                ret, out, err = utils.run_cmd(cmd)
            except Exception as e:
                log.error(e)
                return -1
            if ret != 0:
                log.error(f"cmd {cmd} returned non-zero exit code {ret}")
                log.info(out)
                log.info(err)
                if os.path.exists(self.tmp_install_dir):
                    shutil.rmtree(self.tmp_install_dir)
                return ret
            return 0

    def find_bridges(self):
        log.info(f"Generating bridges for {self.package}")
        if os.path.exists(self.bridges_path) and not self.always:
            log.info(f"Bridges for {self.package} already exist at {self.bridges_path} - Skipping...")
            log.info(f"Use -A to force recreation.")
            return 0
        else:
            if not os.path.exists(self.tmp_install_dir):
                return -1
            bridges_dir = self.bridges_dir
            if not os.path.exists(bridges_dir):
                utils.create_dir(bridges_dir)
            cmd = [
                'node',
                GASKET,
                '-r', self.pkg_inner_dir,
                '-o', self.bridges_path
            ]
            log.info(cmd)
            try:
                ret, out, err = utils.run_cmd(cmd)
            except Exception as e:
                log.error(e)
                log.warn(out)
                log.warn(err)
                return -1
            if ret != 0:
                log.error(f"cmd {cmd} returned non-zero exit code {ret}")
                log.warn(out)
                log.warn(err)
                return ret
            log.info(out)
            log.info(err)

        return 0

    def install_package_build_from_source(self):
        log.info(f"Installing (BUILD-FROM-SOURCE) {self.package}")
        # XXX: Remove old installation (prebuilt). Build from source!
        if os.path.exists(self.tmp_install_dir):
            shutil.rmtree(self.tmp_install_dir)
        utils.create_dir(self.tmp_install_dir)
        cmd = [
            'npm',
            'install',
            '--build-from-source',
            '--prefix', self.tmp_install_dir,
            "{}@{}".format(self.name, self.version)
        ]
        log.info(cmd)
        try:
            ret, out, err = utils.run_cmd(cmd)
        except Exception as e:
            log.error(e)
            return -1
        if ret != 0:
            log.error(f"cmd {cmd} returned non-zero exit code {ret}")
            log.info(out)
            log.info(err)
            if os.path.exists(self.tmp_install_dir):
                shutil.rmtree(self.tmp_install_dir)
            return ret
        return 0

    def check_bridges(self):
        log.info(f"Checking bridges for {self.package}, ensuring not failed/stripped")
        self.stripped = False
        bridges_json_path = self.bridges_path
        if os.path.exists(bridges_json_path):
            with open(bridges_json_path, 'r') as infile:
                bridges_orig_raw = json.loads(infile.read())
            bridges_orig = bridges_orig_raw['bridges']
            modules_orig = bridges_orig_raw['modules']

            if (len(modules_orig) == 0) or (len(bridges_orig) == 0):
                self.stripped = True
                return -1
            failed_orig = bridges_orig_raw['failed']

            jsnames_ok = set()

            for b in bridges_orig:
                # XXX: Add final comp
                jsnames_ok.add(b['jsname'].split('.')[-1])

            for k,v in failed_orig.items():
                kk = k.split('.')[-1]
                if v == 'CFUNC_ADDRESS_RESOLUTION' and kk not in jsnames_ok:
                    log.warning(f"jsname = {kk} not in bridges while having rebuilt")
                    self.stripped = True
                    return -1
            return 0
        else:
            # XXX: analyze_module.js blew up. No bridges were generated.
            return -1

    def generate_bridges_csv(self):
        log.info(f"Generating CSV bridges for {self.package}")
        if os.path.exists(self.bridges_csv_path) and not self.always:
            log.info(f"Bridges .txt for {self.package} already exist at {self.bridges_csv_path} - Skipping...")
            log.info(f"Use -A to force recreation.")
            return 0
        else:
            bridges_json_path = self.bridges_path
            bridges_new = set()
            with open(bridges_json_path, 'r') as infile:
                bridges_orig_raw = json.loads(infile.read())
            bridges_orig = bridges_orig_raw['bridges']
            for b in bridges_orig:
                jsname = b['jsname']
                cfunc = b['cfunc']

                # XXX: Keep only basename.
                new_jsname = jsname.split('.')[-1].split('/')[-1]
                # XXX: Keep only "last" function name.
                #      Obliterate namespaces ("::")
                #      Obliterate arg types ("(int...)")
                match = re.search(r"(?:\w+::)?(\w+)(?:\(|$)", cfunc)
                if match:
                    new_cfunc = match.group(1)
                else:
                    log.error(f"Couldn't exract new jsname/cfunc for bridge: {b}")
                    return -1

                bridges_new.add((new_jsname, new_cfunc))

            with open(self.bridges_csv_path, 'w') as outfile:
                for bn in bridges_new:
                    j = bn[0]
                    c = bn[1]
                    outfile.write(f'({j},{c})\n')
                outfile.flush()
            return 0

    def process(self):
        log.info(f"Processing package: '{self.package}'")
        if os.path.exists(self.bridges_csv_path) and not self.always:
            log.info(f"Bridges .txt for {self.package} already exist at {self.bridges_csv_path} - Skipping...")
            log.info(f"Use -A to force recreation.")
            return 0

        ret = self.install_package()
        if ret != 0:
            return ret

        rebuilt = False

        ret = self.find_bridges()
        if ret != 0:
            log.warning(f"Bridge generation failed for {self.package}. Reinstalling from source...")
            # XXX: Remove old bridges.
            if os.path.exists(self.bridges_dir):
                shutil.rmtree(self.bridges_dir)
            ret = self.install_package_build_from_source()
            if ret != 0:
                return ret
            rebuilt = True
            ret = self.find_bridges()
            if ret != 0:
                return ret

        ret = self.check_bridges()
        if ret < 0 and not rebuilt:
            if self.stripped:
                log.warning(f"Package {self.package} is stripped. Reinstalling from source...")
                # XXX: Remove old bridges.
                if os.path.exists(self.bridges_dir):
                    shutil.rmtree(self.bridges_dir)
                ret = self.install_package_build_from_source()
                if ret != 0:
                    return ret
                ret = self.find_bridges()
                if ret != 0:
                    return ret

        ret = self.check_bridges()
        if ret != 0:
            return ret

        ret = self.generate_bridges_csv()
        if ret != 0:
            return ret

        return ret

def do_single(p, always):
    log.info(f"Processing package '{p}'")
    bridger = JavascriptBridger(p, always)
    bridger.process()

def main():
    args = parse_args()
    setup_logging(args)

    if args.input is None:
        log.error("Must provide input CSV file")
        sys.exit(1)

    package_names = utils.load_csv(args.input)

    for pkg in package_names:
        do_single(pkg, args.always)


if __name__ == "__main__":
    main()

