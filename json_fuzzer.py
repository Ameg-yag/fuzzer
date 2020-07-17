import sys
import os
from pwn import *
import json
import random 
from helper import *


def read_json(inputFile):
	# currently read as string
	with open(inputFile) as file:
		return ''.join(file.readlines())

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
	empty(binary)
	# invalid json
	invaild_json(binary)
	# bit flips 

	# format strings 

	# overflows strings 

	# overflow intergers 

	# 



	

