import sys
import os

import copy
import xml
import xml.etree.ElementTree as ET

from pwn import *

from helper import *

class XMLFuzzer:
    def __init__(self, input):
        try:
            self._xml = ET.parse(input).getroot()
        except Exception as e:
            print(e)

    def _bitflip(self, xml):
        bytes = bytearray(xml, 'UTF-8')

        for i in range(0, len(bytes)):
            if random.randint(0, 20) == 1:
                bytes[i] ^= random.getrandbits(7)
            
        return bytes.decode('ascii')

    def _add(self, xml):
        return

    def _mutate(self, child, function):
        root = copy.deepcopy(self._xml)

        # remove the given node from the root
        def remove():
            root.remove(root.find(child.tag))

        # duplicate the given node a random number of times at the end
        def duplicate():
            for i in range(0, random.randint(0, 100)):
                root.append(copy.deepcopy(child))

        # move the given node to the end of the input
        def move():
            root.remove(root.find(child.tag))
            root.append(copy.deepcopy(child))

        switch = {
            0: remove(),
            1: duplicate(),
            2: move()
        }
        switch.get(function)

        return root

    def generate_input(self):
        # test how the binary reacts to no input
        yield ""

        # test random input (invalid XML)
        yield "ABC123"
        yield "ABC123" * 100

        # Test modifying the test input
        for child in self._xml:
            # test removing some of the test input
            yield ET.tostring(self._mutate(child, 0)).decode()

            # test duplicating some nodes
            yield ET.tostring(self._mutate(child, 1)).decode()

            # test moving some of the existing nodes around
            yield ET.tostring(self._mutate(child, 2)).decode()

            # test adding some additional information to the child
            #yield ET.tostring(self._mutate(child, 3)). decode()

        # test adding more nodes
        # yield ET.tostring(self._add(self._xml)).decode()

        # test random bitflips on the input
        for i in range(0, 100000):
            yield self._bitflip(ET.tostring(self._xml).decode())

def xml_fuzzer(binary, inputFile):
    context.log_level = 'WARNING'

    with open(inputFile) as input:
        for test_input in XMLFuzzer(input).generate_input():
            test_payload(binary, test_input)
            #print(">" + test_input + "\n")

