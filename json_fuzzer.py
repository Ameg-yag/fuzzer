import sys
import os
from pwn import *
import json
import random 


def read_json(inputFile):
	# currently read as string
	with open(inputFile) as file:
		return ''.join(file.readlines())

def check_process(p,output):
	p.proc.stdin.close()
	if p.poll(block=True) < 0:
		print("Found something..., saving to file bad.txt")
		out = open("./bad.txt", "w")
		out.writelines(output)
		out.close()
		exit()

def empty_json(binary):
	p = process(binary)
	p.send("")
	check_process(p,"")

def invaild_json(binary):
	p = process(binary)
	out = b''
	for x in range(0, 1000):
		out += chr(random.randrange(0,255))
	p.send(out)
	check_process(p,out)

def json_fuzzer(binary, inputFile):

	json_input = read_json(inputFile)
	# check nothing 
	empty_json(binary)
	# invalid json
	invaild_json(binary)
	# bit flips 

	# format strings 

	# overflows 

	

