#!/usr/bin/env python3

import sys
import os
from pwn import *

# argument error checking
    # 1 = binary name
    # 2 = sampleinput


PATH_TO_SANDBOX = "binaries/" # make empty string for deployment

if (len(sys.argv) != 3):
    sys.exit("Usage: python3 fuzzer.py [binaryName] [sampleInput]")

binaryFileName = sys.argv[1]
sampleInputFileName = sys.argv[2]


if not (os.path.isfile(PATH_TO_SANDBOX + binaryFileName)):
    sys.exit("Binary does not exist")

if not (os.path.isfile(PATH_TO_SANDBOX + sampleInputFileName)):
    sys.exit('Sample input does not exist')

# open files

