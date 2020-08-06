import sys
import os
from pwn import *
import random 
from helper import *
import itertools

def alpha_perm(length):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return itertools.combinations_with_replacement(alphabet,length)

def num_perm(length):
    alphabet = "0123456789"
    return itertools.combinations_with_replacement(alphabet,length)

def alphanum_perm(length):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return itertools.combinations_with_replacement(alphabet,length)

def defined_perm(alphabet, length):
    return itertools.combinations_with_replacement(alphabet[:-1],length-1) # do not include trailing \n

def defined_num_perm(alphabet, length):
    try:
        int(alphabet[:-1])
    except ValueError:
        return alphabet[:-1]
    print("detected: {}",int(alphabet[:-1]))
    return range(-5000,5000,10)

def txt_fuzzer(binary, inputFile):

    print("plaintext detected")

    # Ordered by speed of execution and likelihood of success

    ## Basic functions
    # Empty
    empty(binary)

    # Overflow
    for i in range(13):
        test_payload(binary,cyclic(1<<i))

    ## Mutation Based

    # Mutate numbers only

    with open(inputFile) as f:
        perm_inputs = []
        for line in f.readlines():
            perm_lines = []
            for perm_line in defined_num_perm(line,len(line)):
                if(type(perm_line) == int):
                    perm_lines.append("".join(str(perm_line))+'\n')
                else:
                    perm_lines.append(line)
                    break
            perm_inputs.append(perm_lines)

        if(len(perm_inputs)> 1):
            payloads = itertools.product(perm_inputs[0],perm_inputs[1])
        else:
            payloads=perm_inputs[0]

        for payload in payloads:
            print("".join(payload).encode())
            test_payload(binary, "".join(payload).encode())

    # Mutate everything

    with open(inputFile) as f:
        perm_inputs = []
        for line in f.readlines():
            perm_lines = []
            for perm_line in defined_perm(line,len(line)):
                perm_lines.append("".join(perm_line)+'\n')
            perm_inputs.append(perm_lines)

        if(len(perm_inputs)> 1):
            payloads = itertools.product(perm_inputs[0],perm_inputs[1])
        else:
            payloads=perm_inputs[0]

        for payload in payloads:
            print("".join(payload).encode())
            test_payload(binary, "".join(payload).encode())

    # generational mutation

    # Basic Alphabet Permutation of various lengths
    for i in range(4):
        for payload in alpha_perm(i):
            test_payload(binary,"".join(payload).encode())

    # Basic Numeric Permutation of various lengths
    for i in range(4):
        for payload in num_perm(i):
            test_payload(binary,"".join(payload).encode())

    # Basic Alphanumeric Permuation of various lengths
    for i in range(4):
        for payload in alphanum_perm(i):
            test_payload(binary,"".join(payload).encode())
        
    print("Couldn't fuzz!")


    
    