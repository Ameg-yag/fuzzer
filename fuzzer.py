#!/usr/bin/env python3

import sys
import os
from pwn import *
import csv 
import json
import random 

# argument error checking
    # 1 = binary name
    # 2 = sampleinput

PATH_TO_SANDBOX = "binaries/" # make empty string for deployment

if (len(sys.argv) != 3):
    sys.exit("Usage: python3 fuzzer.py [binaryName] [sampleInput]")

binaryFileName = sys.argv[1]
print("Binary: " + binaryFileName)
sampleInputFileName = sys.argv[2]
print("Input File: " + sampleInputFileName)

binary = PATH_TO_SANDBOX + binaryFileName
if not (os.path.isfile(binary)):
    sys.exit("Binary does not exist")

inputFile = PATH_TO_SANDBOX + sampleInputFileName
if not (os.path.isfile(inputFile)):
    sys.exit('Sample input does not exist')

# open files
# test input to determine file type

# save csv 
csv_input = []

# Read and save csv output 
with open(inputFile) as file:
	reader = csv.reader(file, delimiter=',')
	i = 0
	for row in reader:
		csv_input.append(row)


for x in range(0, 100):
	for x in csv_input[1]:
		string_length = random.randrange(0, 10001)
		out = ""
		for i in range(0, string_length):
			out += chr(random.randrange(0, 255))
		x = out

	p = process(binary)
	for r in csv_input:
		p.send(','.join(r))
	p.proc.stdin.close()
	print("Testing... ", i) 

	if p.poll(block=True) < 0:
		print("Found something..., saving to file bas.txt")
		out = open("./bad.txt", w)
		out.writelines([output])
		out.close()
		exit()

	p.close()

print("No vulnerabilties found")







