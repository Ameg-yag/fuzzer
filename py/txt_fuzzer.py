from helper import test_payload, empty, cyclic
import itertools

def alpha_perm(length):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"
    return itertools.combinations_with_replacement(alphabet,length)

def num_perm(length):
    alphabet = "0123456789\n"
    return itertools.combinations_with_replacement(alphabet,length)

def alphanum_perm(length):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"
    return itertools.combinations_with_replacement(alphabet,length)

def defined_perm(alphabet, length):
    return itertools.combinations_with_replacement(alphabet[:-1],length-1) # do not include trailing \n

def defined_num_perm(alphabet, length, start, stop, speed):
    try:
        int(alphabet[:-1])
    except ValueError:
        return alphabet[:-1]
    return range(start,stop,speed)

def txt_fuzzer(binary, inputFile):

    print("plaintext detected")

    # Ordered by speed of execution and likelihood of success

    ## Basic functions
    # Empty
    empty(binary)

    line_cnt = len(open(inputFile).readlines())

    # Overflow
    for i in range(13):
        payload = b''
        for _ in range(line_cnt):
            payload += cyclic(1<<i)+b'\n'
        test_payload(binary,payload)

    # Format String
    with open(inputFile) as f:
        num_lines = len(f.readlines())
        payload = b'%10$s %100$s %1000$s %10$p %100$p %1000$p\n'*num_lines
        test_payload(binary,payload)

    ## Mutation Based

    # Mutate numbers only (SLOW FINE GRAIN)

    with open(inputFile) as f:
        perm_inputs = []
        for line in f.readlines():
            perm_lines = []
            for perm_line in defined_num_perm(line,len(line),-100,100,1):
                if(type(perm_line) == int):
                    perm_lines.append("".join(str(perm_line))+'\n')
                else:
                    perm_lines.append(line)
                    break
            perm_inputs.append(perm_lines)

        if(len(perm_inputs)> 1):
            payloads = list(itertools.product(*perm_inputs))
        else:
            payloads=perm_inputs[0]

        for payload in list(payloads):
            test_payload(binary, "".join(payload).encode())

    # Mutate numbers only (FAST WIDE SWEEP)

    with open(inputFile) as f:
        perm_inputs = []
        for line in f.readlines():
            perm_lines = []
            for perm_line in defined_num_perm(line,len(line),-5000,5000,10):
                if(type(perm_line) == int):
                    perm_lines.append("".join(str(perm_line))+'\n')
                else:
                    perm_lines.append(line)
                    break
            perm_inputs.append(perm_lines)

        if(len(perm_inputs)> 1):
            payloads = list(itertools.product(*perm_inputs))
        else:
            payloads=perm_inputs[0]

        for payload in list(payloads):
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
            payloads = list(itertools.product(*perm_inputs))
        else:
            payloads=perm_inputs[0]

        for payload in payloads:
            test_payload(binary, "".join(payload).encode())

    # Basic Numeric Permutation of various lengths
    for i in range(5):
        for payload in num_perm(i):
            test_payload(binary,"".join(payload).encode())

    # Basic Alphabet Permutation of various lengths
    for i in range(4):
        for payload in alpha_perm(i):
            test_payload(binary,"".join(payload).encode())

    # Basic Alphanumeric Permuation of various lengths
    for i in range(4):
        for payload in alphanum_perm(i):
            test_payload(binary,"".join(payload).encode())
        
    print("Couldn't fuzz!")


    
    