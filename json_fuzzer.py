import sys
import os
from pwn import *
import json
import random 
from helper import *


def read_json(inputFile):
	# currently read as string
	with open(inputFile) as file:
		return json.load(file)

def invaild_json(binary):
	out = b''
	payload = ""
	for x in range(0, 1000):
		payload += chr(random.randrange(0,255))
	out += payload.encode('UTF-8')
	test_payload(binary, out)

# performs type swaps on ints and strings in root level of json dict
def swap_json_values(json_object):
	for key in json_object:
		try:
			json_object[key] += 1
			json_object[key] = get_random_string(randint(2, 10))
		except TypeError:
			if type(json_object[key]) is dict:
				json_object[key] = swap_json_values(json_object[key])
			else:
				json_object[key] = randint(2, 10)
	return json_object

def wrong_type_values_json(binary, json_input):
	payload = b''
	payload += json.dumps(swap_json_values(json_input)).encode('UTF-8')
	test_payload(binary, payload)

def change_field_amount_json(binary, json_object):
	jsonEntriesCount = len(json_object.keys())

	# removing different entries amount of entries
	for i in range(jsonEntriesCount):
		copy = json_object.copy()
		for x in range(i):
			del copy[list(json_object.keys())[x]]     # have chosen not to sort to have different subsets of fields removed (more random impact ?)
		payload = json.dumps(copy).encode('UTF-8')
		test_payload(binary, payload)
	
	# add additional entries
	for i in range(25):
		copy = json_object.copy()
		for x in range(i):
			chance = randint(0, 1)
			if (chance):
				copy[get_random_string(10)] = get_random_string(5)
			else:
				copy[get_random_string(10)] = randint(0, 262144)
		payload = json.dumps(copy).encode('UTF-8')
		test_payload(binary, payload)


def json_fuzzer(binary, inputFile):
	json_input = read_json(inputFile)
	# dumb fuzzing
	## check empty payload
	empty(binary)
	## invalid json
	invaild_json(binary)
	## lots of random fields and things


	# smart fuzzing
	## nullify fields - zero and empty strings

	## create extra fields & delete some
	change_field_amount_json(binary, json_input)
	## swapping expected types - works for high level and sub dictionaries
	wrong_type_values_json(binary, json_input)
	## format strings 

	# overflow strings 

	# overflow intergers 

	# 



	

