#!/usr/bin/env python

from __future__ import print_function

import errno
import json
import os
import re
import sys

_INCLUDE_PATH = '/usr/include/asm/unistd_64.h'

my_dir = os.path.dirname(__file__)
data_dir = os.path.join(my_dir, 'data')
syscall_path = os.path.join(data_dir, 'syscalls_x64.json')
try:
    os.makedirs(data_dir, mode=0o755)
except OSError as e:
    if e.errno != errno.EEXIST:
        raise OSError


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: {} path/to/unistd_XX.h\nExample: {} {}'.format(sys.argv[0], sys.argv[0], _INCLUDE_PATH))
        exit()

    header_path = sys.argv[1]
    header = open(header_path, 'r').read()
    syscalls = {}
    for match in re.finditer(r'__NR_(\w+)\s+(\d+)', header):
        name = match.group(1)
        value = int(match.group(2))
        syscalls[value] = name
    json.dump(syscalls, open(syscall_path, 'w'))
