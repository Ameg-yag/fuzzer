from pwn import *
import csv 
import json
import xml.etree.ElementTree as ET
import multiprocessing
import threading


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

def is_csv(file):    # CSV sometimes thinks plaintext == CSV
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
		os._exit(1)

def get_random_string(length):
    letters = string.ascii_lowercase
    letters += string.ascii_uppercase
    new_str = ''.join(random.choice(letters) for i in range(length))
    return new_str

def test_payload(binary, payload):

    if(threading.current_thread() is threading.main_thread() and threading.activeCount() < multiprocessing.cpu_count()):
        threading._start_new_thread(test_payload,(binary,payload))

    else:
        p = process(binary)
        # test payload is byte array
        try:
            payload = payload.decode()
        except (UnicodeDecodeError, AttributeError):
            exit("payload is not a byte string")
        p.send(payload)
        check_process(p, payload)
        p.close()