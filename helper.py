from pwn import *
import csv 
import json
import xml.etree.ElementTree as ET

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
    return True

def is_xml(file):
    try:
        file.seek(0)
        xmlObj = ET.parse(file)
    except:
        return False
    return True

def check_process(p,output):
	p.proc.stdin.close()
	if p.poll(block=True) < 0:
		print("Found something... saving to file bad.txt")
		out = open("./bad.txt", "w")
		out.writelines(output)
		out.close()
		exit()