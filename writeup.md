Fuzzer
===========

# Design Approach
This assignment requires the design of a fuzzer to test binaries and elicit unexpected behaviour or errors.
The general principle of a fuzzer is to test a wide variety of input data and elicit unexpected behaviour from improper handling of input data.

In this assignment we have decided to use python to build the fuzzer. We have split the complexity of the fuzzer into 'dumb fuzzing' and 'smart fuzzing'. Dumb fuzzing is where the sample input is not used and you send payloads such as empty payloads and random character payloads of varying sizes. 'Smart Fuzzing' is manipulating the sample input in order to evoke more complex errors such as int over/underflows and format strings etc. This is able to be performed with smart fuzzing as you are directly modifying the input the binary is expected to receive in a similar format. The fuzzers are separated via input type (`json, csv, xml, plaintext`). Many of the ideas to evoke bad behaviour from these inputs are similar. Ideas such as:
- Incorrect input type (int instead of str)
- Buffer overflow (string too large)
- Int over/underflow (int too large or too small)
- Format Strings (string input not correctly handled)

From these we have implemented similar functionality in each of the input-type dependent methods, using these attacks in a manner we think is appropriate for the input data type.

For areas of dumb fuzzing, we have tried to factor the code so code duplication is kept minimal (common function for empty payload test), for a clean compact codebase.


# Specific fuzzer implementation details
## JSON Fuzzer
Some details to add about the JSON fuzzer:
- Incorporated a nested dictionary test data input (incase of binary loops)
- checks majority of the common security error ideas (previously listed @Design Approach)
- Creates effective random json files which use specific keys given by the input json exmaple.
- Utilises "None" type available to JSON formatting.


## CSV Fuzzer
The csv fuzzer tries the following to elicit memory corruption:  
- Sending an empty payload 
- Sending an invalid csv file by removing all delimiters
- Sending a CSV payload with increasing number of lines to overflow total input
- Sending different number of fields to overflow number of fields
- Sending a csv file with different delimiters
- Sending payload with increasingly large strings
- Sending format strings in the payload 
- Sending payloads with all 0, negative numbers, large numbers, floats
- Byte Flipping
- Test above with and without altering the header line.


## XML Fuzzer
The XML Fuzzer is currently in early stages of development, but so far it has the following functionality
- Sending non-XML test data (empty string, basic small string (e.g. "ABC") and a very large string ("ABC" * 1000))
- Mutating the supplied test data to attempt to have it a parse an invalid (but in a valid enough format) XML file
    - Removing children nodes, or children of those children nodes
    - Moving the order of children nodes, or duplicating them
- Attempted to add functionality to include unexpected data to valid tags (e.g. format strings in attributes)

## Plaintext fuzzer

## Bonus Marks

# Future Work
