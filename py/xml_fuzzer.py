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

    """
    Modifies the provided child node of the test_input and returns the new test input

    @param child        one of the children nodes of the test input
    @param functions    an array of the following numbers specifying how to mutate
        0: Remove the child from the root
        1: Duplicate the child many times at the end of the XML
        2: Duplicate recursively, appending the child node as a child of itself
        3: Move the specified child to the end of the input
        4: Adds some format strings and buffer overflows to the child node
        5: Removes any children nodes from the specified child
    """
    def _mutate(self, child, functions):

        root = copy.deepcopy(self._xml)     # Don't overwrite the original text
        child = root.find(child.tag)        #

        # remove the given node from the root
        def _remove():
            root.remove(child)

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

        switch = {
            0: _delete_open_tag,
            1: _delete_close_tag,
            2: _replace_numbers
        }

        for i in functions:
            try:
                switch.get(i)()
            except Exception as e:
                print(i)
                print(e)

        return lines

    def generate_input(self):
        # test how the binary reacts to no input
        yield ""

        ###########################################################
        #              Test valid (format) XML data              ##

        # Modify the test input to still be in the correct format for XML
        for child in self._xml:
            for i in range(0, 6):
                yield ET.tostring(self._mutate(child, [i])).decode()

            # test some combinations of the above
            yield ET.tostring(self._mutate(child, [0, 4, 5])).decode()

        # Create some new nodes and add these to the test input
        for i in range(0, 6):
            yield ET.tostring(self._add([i])).decode()

        yield ET.tostring(self._add([0, 1, 2, 3, 4, 5])).decode()

        ############################################################


        ############################################################
        ##             Test invalid (format) XML data             ##

        for i in range(0, 3):
            yield self._replace([i])

        # for i in range(0, 1000):
        #     # test random input (invalid XML)
        #     yield get_random_string((i + 1) * 10)
        #
        #     # test random bitflips on the test input
        #     yield self._byteflip()

        ############################################################

def xml_fuzzer(binary, inputFile):
    context.log_level = 'WARNING'

    with open(inputFile) as input:
        for test_input in XMLFuzzer(input).generate_input():
            out = open("test.txt", "w+")
            out.writelines(test_input)
            out.close()

            try:
                test_payload(binary, test_input)
            except Exception as e:
                print("ASDASDASDSA")
