import sys
import os
from pwn import *
import random 
from helper import *

def txt_fuzzer(binary, inputFile):
    print("plaintext detected")