#!/usr/bin/env python
# -*- coding: utf-8 -*-

import shutil, errno, os, subprocess, argparse

# Cleans up directory by removing it if exists.
def cleanup(dir):
    try:
        shutil.rmtree(dir)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise

# Generates javadoc by using command 'javasphinx-apidoc'.
def javadoc(module):
    outdir = os.path.normpath('javadoc/' +  module)
    indir = os.path.normpath('../' + module + '/src/main/java')
    subprocess.call(['javasphinx-apidoc', '-t', 'Module ' + module, '-o', outdir, indir])

# Compiles documentation to given type by using the make command.
def sphinx(type):
    subprocess.call(['make', type])

# Parses and returns the command line arguments.
def args():
    parser = argparse.ArgumentParser(description='Generate all documentation of ErVerifyTool.')
    parser.add_argument('command', choices=['all', 'clean'], nargs='?',
                        default='all', help='choose command all|clean. default is all')
    return parser.parse_args()

# MAIN PART
args = args()
cleanup('javadoc')
cleanup('_build')
if args.command == 'all':
    javadoc('commons')
    javadoc('cli')
    javadoc('war')
    sphinx('html')
    sphinx('latexpdf')
