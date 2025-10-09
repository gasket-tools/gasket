import os
import csv
import logging
from pathlib import Path
import subprocess as sp

log = logging.getLogger(__name__)

def load_csv(filename):
    package_names = []
    with open(filename, 'r') as file:
        for line in file:
            l = line.strip()
            #XXX: Ignore empty lines
            if l:
                package_names.append(l)
    return package_names

def to_mod_name(name):
    return os.path.splitext(name)[0].replace("/", ".")

def repo_name_to_tuple(pkg):
    parts = pkg.split('/')
    user = parts[0]
    repo = parts[1]
    return (user,repo)

def pkg_name_to_tuple(pkg):
    parts = pkg.split(':')
    name = parts[0]
    version = parts[1]
    return (name,version)

def get_mod_import_name(mod_path, pkg_root_path):

    # XXX: We want to find out the "include" name for the
    #      C-based module.

    if pkg_root_path == 'naked':
        return os.path.basename(mod_path).split('.')[0]

    if mod_path.endswith(".so"):
        first_part = os.path.dirname(mod_path)
        last_part = os.path.basename(mod_path).split('.')[0]
        mod_path = os.path.join(first_part, last_part)

    # print("pkg_root_path = %s" % pkg_root_path)
    # print("last_part of pkg_root_path = %s" % os.path.basename(pkg_root_path))

    rel = os.path.relpath(mod_path, pkg_root_path)
    # print("rel = %s" % rel)
    # print("rel = %s" % rel)
    import_name = os.path.basename(pkg_root_path) + '.' + to_mod_name(rel)

    return import_name

def run_cmd(opts, timeout=None, shell=False):
    cmd = sp.Popen(opts, stdin=sp.DEVNULL, stdout=sp.PIPE, stderr=sp.PIPE, text=True, shell=shell)
    out, err = cmd.communicate(timeout=None)
    ret = cmd.returncode
    log.debug(opts)
    log.debug("ret = %s" % ret)
    log.debug(out)
    log.debug(err)
    return ret, out, err

def create_dir(path):
    p = Path(path)
    if not p.exists():
        p.mkdir(parents=True)

def find_git_root():
    path = Path.cwd()
    if (path/".git").exists():
        return path.as_posix()
    for parent in path.parents:
        if (parent/".git").exists():
            return parent.as_posix()
    return None

def sanitize_package_name(package):
    # Avoid filesystem errors due to packages containing
    # illegal characters  (@augmentality/node-alsa)
    return package.replace("/", "~")

