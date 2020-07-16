#!/usr/bin/env python3

import sys
import os
from pwn import *
import csv 
import json
import random 

def read_csv(file):
	csv_input = []
	# Read and save csv output 
	with open(inputFile) as file:
		reader = csv.reader(file, delimiter=',')
		for row in reader:
			csv_input.append(row)
	return csv_input

def check_process(p,output):
	p.proc.stdin.close()
	if p.poll(block=True) < 0:
		print("Found something..., saving to file bad.txt")
		out = open("./bad.txt", "w")
		out.writelines(output)
		out.close()
		exit()

def empty_csv(binary):
	p = process(binary)
	p.send("")
	check_process(p,"")


def fields_csv(binary, csv_input):
	for field_no in range(1, len(csv_input[0]) + 10):
		p = process(binary)
		error = []
		for x in range(len(csv_input)):
			n = len(csv_input[x])
			if field_no < n:
				for i in range(0, n - field_no): 
					csv_input[x].pop()
			else:
				for i in range(n,field_no):
					csv_input[x].append("A")
			try:
				p.sendline(','.join(csv_input[x]))
			except:
				if x > 0:
					# assumption that sending multiple lines is accpeted no of fields
					# assumption only one right number of fields 
					expected_field_no = x
				break
			error.append( ','.join(csv_input[x]) + '\n')
		check_process(p,error)
		p.close() 
	return expected_field_no

# Check if a enough CSV lines will crash the program 
def lines_csv(binary, csv_input):
	for length in range(0, 1000, 100):
		p = process(binary)
		error = []
		for l in range(0,length):
			if l < len(csv_input):
				p.sendline(','.join(csv_input[l]))
				error.append( ','.join(csv_input[l]) + '\n')
			else:
				p.sendline(','.join(csv_input[len(csv_input) - 1]))
				error.append( ','.join(csv_input[len(csv_input) - 1]) + '\n')

		check_process(p,error)
		p.close()

def csv_fuzzer(binary, inputFile):
	csv_input = read_csv(sampleInputFileName)
	# check nothing 
	empty_csv(binary)
	# check number of lines 
	lines_csv(binary, csv_input)
	# check fields - can return number of expected fields 
	fields_csv(binary, csv_input)


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
# test input to determine input file type

csv_fuzzer(binary, inputFile)







