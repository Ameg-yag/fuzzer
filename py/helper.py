from pwn import *
import csv
import json
import xml.etree.ElementTree as ET
import multiprocessing


def empty(binary):
    test_payload(binary, "")


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

    if (
        csv.excel.delimiter == csvObj.delimiter
        or csv.excel_tab.delimiter == csvObj.delimiter
    ):
        return True

    return False


def is_xml(file):
    file.seek(0)
    try:
        xmlObj = ET.parse(file)
    except Exception:
        return False
    return True


def check_segfault(p, output):
    p.proc.stdin.close()
    if p.poll(block=True) == -11:
        print("Found something... saving to file bad.txt")
        with open("./bad.txt", "w") as out:
            out.write(output)
        return True
    else:
        return False


def get_random_string(length):
    letters = string.ascii_lowercase
    letters += string.ascii_uppercase
    new_str = "".join(random.choice(letters) for i in range(length))
    return new_str


def test_payload(binary, payload):
    # Prepare payload for sending
    # Send binary and payload into a pool
    if not isinstance(payload, str):
        try:
            payload = payload.decode()
        except (UnicodeDecodeError, AttributeError):
            exit("payload is not a byte string")

    # Benchmarking shows that having more processes than cpu cores improves performace, maybe IO bound or waiting while polling
    if (
        len(multiprocessing.active_children()) < multiprocessing.cpu_count() * 2
        and multiprocessing.current_process().name == "MainProcess"
    ):

        p = multiprocessing.Process(target=test_payload, args=(binary, payload))
        p.daemon = True
        p.start()

    else:
        run_test(binary, payload)


def run_test(binary, payload):

    with process(binary) as p:
        # commented because payload doesn't needed to be unicoded
        # test payload is byte array
        p.send(payload)
        if check_segfault(p, payload):
            if multiprocessing.current_process().name != "MainProcess":
                try:
                    os.kill(os.getppid(), signal.SIGTERM)
                except PermissionError:
                    sys.exit()
            else:
                sys.exit()

