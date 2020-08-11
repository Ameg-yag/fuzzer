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
        reader = csv.reader(f, delimiter=",")
        for row in reader:
            csv_input.append(row)
    return csv_input


def fields_csv(binary, csv_input):
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
                test_payload(binary, ",".join(csv_input[x]))
            except:
                if x > 0:
                    # assumption that sending multiple lines is accpeted no of fields
                    # assumption only one right number of fields
                    expected_field_no = x
                break
            error.append(",".join(csv_input[x]) + "\n")
        test_payload(binary, "".join(error))
    return expected_field_no


# Check if a enough CSV lines will crash the program
def lines_csv(binary, csv_input):
    for length in range(0, 1000, 100):
        error = []
        for l in range(0, length):
            if l < len(csv_input):
                test_payload(binary, ",".join(csv_input[l]))
                error.append(",".join(csv_input[l]) + "\n")
            else:
                test_payload(binary, ",".join(csv_input[len(csv_input) - 1]))
                error.append(",".join(csv_input[len(csv_input) - 1]) + "\n")

        test_payload(binary, "".join(error))

# remove all delimiters make file invalid 
def remove_delimiters(binary, csv_input):
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


def csv_fuzzer(binary, inputFile):
    csv_input = read_csv(inputFile)
    # check nothing
    empty(binary)
    # invalid csv - remove all delimiters 
    remove_delimiters(binary, csv_input)
    # check number of lines
    lines_csv(binary, csv_input)
    # check fields - can return number of expected fields
    fields_csv(binary, csv_input)
    # change delimiters
    change_delimiters(binary, csv_input)
    # bit flipping
    
    # overflowing
    
    # unexcepeted values

    # string format 

    # change first line

    # overflow intergers 

    # overflow strings

    # random types of 

