from pwn import *
import csv
import json
import xml.etree.ElementTree as ET
import multiprocessing

def empty(binary):
	p = process(binary)
	p.send("")
	check_process(p,"")

def is_json(file):
    try:
        file.seek(0)
        jsonObj = json.load(file)
    except ValueError as e:
        return False
    return True

def is_csv(file):
    try:
        file.seek(0)
        csvObj = csv.Sniffer().sniff(file.read(1024))
    except csv.Error:
        return False

    if(csv.excel.delimiter == csvObj.delimiter or \
        csv.excel_tab.delimiter == csvObj.delimiter):
        return True

    return False

def is_xml(file):
    try:
        file.seek(0)
        xmlObj = ET.parse(file)
    except:
        return False
    return True

def check_process(p,output):
    p.proc.stdin.close()
    if (p.poll(block=True) == -11):
        print("Found something... saving to file bad.txt")
        out = open("./bad.txt", "w")
        out.writelines(output)
        out.close()
        if multiprocessing.current_process().name != 'MainProcess':
            try:
                os._exit
            except PermissionError:
                sys.exit()
        sys.exit()

def get_random_string(length):
    letters = string.ascii_lowercase
    letters += string.ascii_uppercase
    new_str = ''.join(random.choice(letters) for i in range(length))
    return new_str

def test_payload(binary, payload):
    # Benchmarking shows that having more processes than cpu cores improves performace, maybe IO bound or waiting while polling
    if(len(multiprocessing.active_children()) < multiprocessing.cpu_count()*2 and \
        multiprocessing.current_process().name == 'MainProcess'):

        p = multiprocessing.Process(target=test_payload,args=(binary,payload))
        p.daemon=True
        p.start()

    else:
	    p = process(binary)
	    # commented because payload doesn't needed to be unicoded
	    # test payload is byte array
	    if type(payload) != str:
	        try:
	            payload = payload.decode()
	        except (UnicodeDecodeError, AttributeError):
	            exit("payload is not a byte string")
	    p.send(payload)
	    check_process(p, payload)
	    p.close()
