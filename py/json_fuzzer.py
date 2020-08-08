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
    out = b""
    payload = ""
    for x in range(0, 1000):
        payload += chr(random.randrange(0, 255))
    out += payload.encode("UTF-8")
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
    copy = json_input.copy()
    payload = b""
    payload += json.dumps(swap_json_values(copy)).encode("UTF-8")
    test_payload(binary, payload)


def change_field_amount_json(binary, json_object):
    jsonEntriesCount = len(json_object.keys())

    # removing different entries amount of entries
    for i in range(jsonEntriesCount):
        copy = json_object.copy()
        for x in range(i):
            del copy[
                list(json_object.keys())[x]
            ]  # have chosen not to sort to have different subsets of fields removed (more random impact ?)
        payload = json.dumps(copy).encode("UTF-8")
        test_payload(binary, payload)

    # add additional entries
    for i in range(25):
        copy = json_object.copy()
        for x in range(i):
            chance = randint(0, 1)
            if chance:
                copy[get_random_string(10)] = get_random_string(5)
            else:
                copy[get_random_string(10)] = randint(0, 262144)
        payload = json.dumps(copy).encode("UTF-8")
        test_payload(binary, payload)


def nullify_json(binary, json_input):
    copy = json_input.copy()
    # set inputs to 0 equivelants
    for key in copy.keys():
        try:
            copy[key] += 1
            copy[key] = 0
        except TypeError:
            if type(copy[key]) is dict:
                copy[key] = []
            else:
                copy[key] = ""
    payload = json.dumps(copy).encode("UTF-8")
    test_payload(binary, payload)
    # set all to null
    copy = json_input.copy()
    for key in copy.keys():
        copy[key] = None
    payload = json.dumps(copy).encode("UTF-8")
    test_payload(binary, payload)


def random_json(binary):
    d = {}
    for i in range(100):
        chance = randint(0, 3)
        if chance == 0:
            d[get_random_string(5)] = None
        elif chance == 1:
            d[get_random_string(5)] = get_random_string(6)
        elif chance == 2:
            d[get_random_string(5)] = randint(0, 1024)
        elif chance == 3:
            d[get_random_string(5)] = deep_nested_json({}, 32)
    payload = json.dumps(d).encode("UTF-8")
    test_payload(binary, payload)


def deep_nested_json(dictionary, length):
    if length == 0:
        return randint(0, 1024)
    else:
        dictionary[get_random_string(8)] = deep_nested_json({}, length - 1)
    return dictionary


def overflow_strings_json(binary, json_input):
    copy = json_input.copy()
    for key in copy.keys():
        try:
            copy[key] += 1
            copy[key] -= 1
        except TypeError:
            if type(copy[key]) is str:
                copy[key] = get_random_string(1025)
    payload = json.dumps(copy).encode("UTF-8")
    test_payload(binary, payload)


def overflow_integers_json(binary, json_input):
	keys = list(json_input.keys())
	for i in range(len(keys)):
		copy = json_input.copy()
		try:
			copy[keys[i]] += 1
			copy[keys[i]]  = 429496729
		except TypeError:
			continue
		payload = json.dumps(copy).encode('UTF-8')
		test_payload(binary, payload)
	copy = json_input.copy()
	for key in copy.keys():
		try:
			copy[key] += 1
			copy[key]  = 429496729
		except TypeError:
			continue
	payload = json.dumps(copy).encode('UTF-8')
	test_payload(binary, payload)

def get_random_format_string(size):
	format_string_identifiers = ["%x", "%c", "%d", "%p"]
	payload = b""
	for i in range(size):
		payload += random.choice(format_string_identifiers)
	print(payload)
	return payload

def format_string_fuzz(binary, json_input):
	copy = json_input.copy()
	for key in copy.keys():
		if type(copy[key]) is str:
			copy[key] = get_random_format_string(64)
	payload = json.dumps(copy).encode('UTF-8')
	test_payload(binary, payload)

#def swap_json_fields(binary, json_input):


def json_fuzzer(binary, inputFile):
	json_input = read_json(inputFile)

	# dumb fuzzing
	## check empty payload
	empty(binary)
	## invalid json
	invaild_json(binary)
	## lots of random fields and things
	random_json(binary)

	# smart fuzzing
	## nullify fields - zero and empty strings
	nullify_json(binary, json_input)
	## create extra fields & delete some
	change_field_amount_json(binary, json_input)
	## swapping expected data types - works for high level and sub dictionaries
	wrong_type_values_json(binary, json_input)
	## format strings
	format_string_fuzz(binary, json_input)
	## overflow strings 
	overflow_strings_json(binary, json_input)
	## overflow integers 
	overflow_integers_json(binary, json_input)
	## swap fields

