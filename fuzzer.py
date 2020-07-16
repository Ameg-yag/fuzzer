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
	p = process(binary)
	error = []
	p.sendline(','.join(csv_input[i]))
	error.append( ','.join(csv_input[i]))
	error.append('\n')
	p.send('')
	for string_length in range(1, 10000, 10):
		for x in range(len(csv_input[1])):
			out = ""
			for i in range(0, string_length):
				out += chr(random.randrange(0x41, 0x42))
			csv_input[1][x] = out
	
		for r in range(1, len(csv_input)):
			output = b""
			output += ','.join(csv_input[r])
			print(output)
			p.sendline(output)
			error.append(output)
			error.append('\n')
			if p.poll(block = False) != None:
				break;

		print("Testing... ", csv_input) 
		if p.poll(block = False) != None:
			break


	p.proc.stdin.close()
	if p.poll(block=True) < 0:
		print("Found something..., saving to file bad.txt")
		out = open("./bad.txt", "w")
		out.writelines(error)
		out.close()
		exit()


	p.close()

	print("No vulnerabilties found")

def fields_csv(binary, csv_input):
	
	p = process(binary)
	error = []
	p.sendline(','.join(csv_input[i]))
	error.append( ','.join(csv_input[i]))
	error.append('\n')
	p.send('')
	for string_length in range(1, 10000, 10):
		for x in range(len(csv_input[1])):
			out = ""
			for i in range(0, string_length):
				out += chr(random.randrange(0x41, 0x42))
			csv_input[1][x] = out
	
		for r in range(1, len(csv_input)):
			output = b""
			output += ','.join(csv_input[r])
			print(output)
			p.sendline(output)
			error.append(output)
			error.append('\n')
			if p.poll(block = False) != None:
				break;

		print("Testing... ", csv_input) 
		if p.poll(block = False) != None:
			break

	check_process(p,output)
	p.close()

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
	# check fields
	lines_csv(binary, csv_input)


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







