import sys
import os

import re
import copy
import xml
import xml.etree.ElementTree as ET

from pwn import *
from helper import *

class XMLFuzzer:
    def __init__(self, input):
        try:
            self._xml = ET.parse(input).getroot()
            self._text = ET.tostring(self._xml)
        except Exception as e:
            print(e)

    def _byteflip(self):
        bytes = bytearray(ET.tostring(self._xml).decode(), 'UTF-8')

        for i in range(0, len(bytes)):
            if random.randint(0, 20) == 1:
                bytes[i] ^= random.getrandbits(7)

        return bytes.decode('ascii')

    def _add(self, functions):
        root = copy.deepcopy(self._xml)
        child = ET.SubElement(root, 'div')

        def _add_links():
            # Forge some wierd links on a new child node
            child.set("%s" * 4, "%s" * 4)
            child.set("id", "%s" * 4)
            content = ET.SubElement(child, 'a')
            content.set("a href", "http://" + "%s" * 4 +  ".com")

        def _add_overflow():
            content = ET.SubElement(child, 'a')
            content.set("a href", "https://" + "A" * 0x1000 + ".com")

        def _add_int_overflow():
            content = ET.SubElement(child, 'a')
            content.set("a", str(2 ** 65 + 1))

        def _add_int_underflow():
            content = ET.SubElement(child, 'a')
            content.set("a", str(2 ** 65))

        def _child_name_overflow():
            child = ET.SubElement(root, "A" * 0x1000)

        def _child_name_fstring():
            child = ET.SubElement(root, "%s" * 0x1000)

        switch = {
            0: _add_links,
            1: _add_overflow,
            2: _add_int_overflow,
            3: _add_int_underflow,
            4: _child_name_overflow,
            5: _child_name_fstring
        }

        for i in functions:
            try:
                switch.get(i)()
                root.append(child)
            except Exception as e:
                print(i)
                print(e)

        return root

    def _mutate(self, child, functions):
        root = copy.deepcopy(self._xml)     # Don't overwrite the original text
        child = root.find(child.tag)        #

        # remove the given node from the root
        def _remove():
            root.remove(root.find(child.tag))

        # duplicate the given node a random number of times at the end
        def _duplicate():
            for i in range(0, random.randint(50, 100)):
                root.append(copy.deepcopy(child))

        # create a line of children nodes starting from the provided child
        def _duplicate_recursively():
            _root = child
            for i in range(0, random.randint(50, 100)):
                _child = copy.deepcopy(_root)
                _root.append(_child)
                _root = _child

        # move the given node to the end of the input
        def _move():
            root.remove(root.find(child.tag))
            root.append(copy.deepcopy(child))

        # Add some more information to each node
        def _add_info():
            child.set("%x" * 100, "B" * 1000)
            child.set("A" * 1000, "%s" * 100)
            child.set("-" + "1" * 1000, "2" * 1000)

            # check if 32 or 64 bit.
            # if(pbits == 32):
            #     print("this")
            #     child.set(p32(0x41414141), p32(0x00000000))
            # else:
            #     child.set(p64(0x4141414141414141), p64(0x0000000000000000))

        # remove all children (grandchildren of root if thats the correct term) from the child
        def _remove_child():
            for grandchild in child:
                child.remove(grandchild)

        # Now the code looks messy because python has no switch/case statement. V nice
        switch = {
            0: _remove,
            1: _duplicate,
            2: _duplicate_recursively,
            3: _move,
            4: _add_info,
            5: _remove_child
        }

        for i in functions:
            try:
                switch.get(i)()
            except Exception as e:
                print(i)
                print(e)

        return root

    def _replace(self, functions):
        lines = self._text.decode()

        def _delete_open_tag():
            nonlocal lines
            lines = re.sub("<[^>]+>", "", lines)

        def _delete_close_tag():
            nonlocal lines
            lines = re.sub("</[^>]+>", "", lines)

        def _replace_numbers():
            nonlocal lines
            lines = re.sub("\b[0-9]+\b", "1000000000", lines)

        switcher = {
            0: _delete_open_tag,
            1: _delete_close_tag,
            2: _replace_numbers
        }

        for i in functions:
            try:
                switcher.get(i)()
            except Exception as e:
                print(i)
                print(e)

        return lines

    def generate_input(self):
        # test how the binary reacts to no input
        # yield ""

        ###########################################################
        #              Test valid (format) XML data              ##

        # # Test modifying the test input
        # for child in self._xml:
        #     # test removing some of the test input
        #     yield ET.tostring(self._mutate(child, [0])).decode()
        #
        #     # test duplicating some nodes
        #     yield ET.tostring(self._mutate(child, [1])).decode()
        #
        #     # test duplicating some nodes
        #     yield ET.tostring(self._mutate(child, [2])).decode()
        #
        #     # test moving some of the existing nodes around
        #     yield ET.tostring(self._mutate(child, [3])).decode()
        #
        #     # test adding some additional information to the child
        #     yield ET.tostring(self._mutate(child, [4])).decode()
        #
        #     # test removing the children of this child node
        #     yield ET.tostring(self._mutate(child, [5])).decode()
        #
        #     # test some combinations of the above
        #     yield ET.tostring(self._mutate(child, [0, 4, 5])).decode()

        # test adding more nodes
        yield ET.tostring(self._add([0])).decode()

        # test adding a wierd node
        yield ET.tostring(self._add([1])).decode()

        yield ET.tostring(self._add([2])).decode()

        yield ET.tostring(self._add([3])).decode()

        yield ET.tostring(self._add([4])).decode()

        yield ET.tostring(self._add([5])).decode()

        ############################################################


        ############################################################
        ##             Test invalid (format) XML data             ##

        # yield self._replace([0])
        # yield self._replace([1])
        # yield self._replace([2])

        # for i in range(0, 1000):
        #     # test random input (invalid XML)
        #     yield get_random_string((i + 1) * 10)

        #     # test random bitflips on the test input
        #     yield self._bitflip()

        ############################################################

def xml_fuzzer(binary, inputFile):
    context.log_level = 'WARNING'

    with open(inputFile) as input:
        for test_input in XMLFuzzer(input).generate_input():
            # print("Testing...", end = '')
            # test = open("test.txt", "w+")
            # test.writelines(test_input)
            # test.close()

            try:
                test_payload(binary, test_input)
            except Exception as e:
                print(e)

            #print("Testing succeeded")

    # xml_fuzzer(binary, inputFile)
