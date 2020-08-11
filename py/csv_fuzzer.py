import sys
import os
from pwn import *
import csv
import random
from helper import *


def read_csv(file):
    csv_input = []
    # Read and save csv output
    with open(file) as f:
        csvObj = csv.Sniffer().sniff(f.read(1024))
        delimiter = csvObj.delimiter
        f.seek(0)
        reader = csv.reader(f, delimiter = delimiter)
        for row in reader:
            csv_input.append(row)
    return csv_input, delimiter


def fields_csv(binary, csv_input, delimiter):
    expected_field_no = -1
    for field_no in range(1, len(csv_input[0]) + 10):
        error = []
        for x in range(len(csv_input)):
            n = len(csv_input[x])
            if field_no < n:
                for _ in range(0, n - field_no):
                    csv_input[x].pop()
            else:
                for _ in range(n, field_no):
                    csv_input[x].append("A")
            try:
                test_payload(binary, delimiter.join(csv_input[x]))
            except:
                if x > 0:
                    # assumption that sending multiple lines is accpeted no of fields
                    # assumption only one right number of fields
                    expected_field_no = x
                break
            error.append(delimiter.join(csv_input[x]) + "\n")
        test_payload(binary, "".join(error))
    return expected_field_no


# Check if a enough CSV lines will crash the program
def lines_csv(binary, csv_input, delimiter):
    for length in range(0, 1000, 100):
        error = []
        for l in range(0, length):
            if l < len(csv_input):
                test_payload(binary, delimiter.join(csv_input[l]))
                error.append(delimiter.join(csv_input[l]) + "\n")
            else:
                test_payload(binary, delimiter.join(csv_input[len(csv_input) - 1]))
                error.append(delimiter.join(csv_input[len(csv_input) - 1]) + "\n")

        test_payload(binary, "".join(error))

# remove all delimiters make file invalid 
def remove_delimiters(binary, csv_input, delimiter):
    payload = ''
    for l in range(0, len(csv_input)):
        payload += "".join(csv_input[l]) + '\n'
    test_payload(binary, payload)


def change_delimiters(binary, csv_input):    
    for x in [" ", ".", ",", "\t", "\n"]:
        payload = ''
        for l in range(0, len(csv_input)):
            payload += x.join(csv_input[l]) + '\n'
        test_payload(binary, payload)

def overflow_fields(binary, csv_input, delimiter):
    for x in range(32, 1000, 32):
        payload = delimiter.join(csv_input[0]) + '\n'
        for l in range(1, len(csv_input)):
            for w in csv_input[l]:
                
                payload += "A"*x + delimiter
            payload = payload[:-1] + "\n"
        test_payload(binary, payload)

def format_string(binary, csv_input, delimiter):
    payload = delimiter.join(csv_input[0]) + '\n'
    for l in range(1, len(csv_input)):
        for w in csv_input[l]:   
            payload += "%p"*32 + delimiter
        payload = payload[:-1] + "\n"
    test_payload(binary, payload)

def change_header(binary, csv_input, delimiter):
    payload = ''
    for l in range(0, len(csv_input)):
        for w in range(0, len(csv_input[l])): 
            payload += get_random_string(25) + delimiter
        payload = payload[:-1] + "\n"
    test_payload(binary, payload)

def overflow_numbers(binary, csv_input, delimiter):
    # zero 
    payload = ''
    payload = delimiter.join(csv_input[0]) + '\n'
    for l in range(1, len(csv_input)):
        for w in range(0, len(csv_input[l])): 
            payload += "0" + delimiter
        payload = payload[:-1] + "\n"
    test_payload(binary, payload)

    # negative numbers 
    payload = ''
    payload = delimiter.join(csv_input[0]) + '\n'
    for l in range(1, len(csv_input)):
        for w in range(0, len(csv_input[l])): 
            payload += str(random.randrange(-4294967296, 0)) + delimiter
        payload = payload[:-1] + "\n"
    print(payload)
    test_payload(binary, payload)

    # high postive numbers 
    payload = ''
    payload = delimiter.join(csv_input[0]) + '\n'
    for l in range(1, len(csv_input)):
        for w in range(0, len(csv_input[l])): 
            payload += str(random.randrange(2147483648,(2**65)))+ delimiter
        payload = payload[:-1] + "\n"
    print(payload)
    test_payload(binary, payload)

    # float
    payload = ''
    payload = delimiter.join(csv_input[0]) + '\n'
    for l in range(1, len(csv_input)):
        for w in range(0, len(csv_input[l])): 
            payload += str(random.random()) + delimiter
        payload = payload[:-1] + "\n"
    print(payload)
    test_payload(binary, payload)


def csv_fuzzer(binary, inputFile):
    csv_input, delimiter = read_csv(inputFile)
    # check nothing
    empty(binary)
    # invalid csv - remove all delimiters 
    remove_delimiters(binary, csv_input, delimiter)
    # check number of lines
    #lines_csv(binary, csv_input, delimiter)
    # check fields - can return number of expected fields
    #fields_csv(binary, csv_input, delimiter)
    # change delimiters
    change_delimiters(binary, csv_input)
    # overflowing fields with string 
    overflow_fields(binary, csv_input, delimiter)
    # string format 
    format_string(binary, csv_input, delimiter)
    # change first line
    change_header(binary, csv_input, delimiter)
    # overflow intergers 
    overflow_numbers(binary, csv_input, delimiter)
    # overflow strings

    # random types of 

    # bit flipping

    # unexcepeted values

