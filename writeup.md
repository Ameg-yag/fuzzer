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
- Incorporated a nested dictionary test data input (incase of loops in binary's input)
- Checks majority of the common security error ideas (previously listed @Design Approach)
- Creates effective random json files which use specific keys (smart fuzzing) given by the input json example.
- Sends empty, garbage variants of data (dumb fuzzing)
- Utilises "None" type available to JSON formatting.
- Format strings, overflows and type misconfigurations are all checked
- All variants of ints are sent, floats, large, small, 0 and negative

The JSON fuzzer fuzzes at a size range which seems reasonable to elicit memory corruption, however, these values could be easily changed which may increase 
the fuzzers effectiveness depending on the types of binaries the fuzzer is being used and tested against.



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
The plaintext fuzzer is similar to other fuzzers but has an additional functionality unique to plaintext files: multiple lines.
Due to the potential of multiple lines, additional processing is taken into consideration to maximise code coverage.
The plaintext fuzzer analyses how many lines are provided and performs fuzzing of each line individually.

The dumb fuzzing functionalities provided are:
- The generation of proceedurally increasing random string inputs
- The generation of proceedurally increasing random numeric inputs
- Format string
- Permutation of all potential 5 digit numbers
- Permutation of all potential 4 character strings
- Permutation of all potential 4 character alphanumeric strings

The smart fuzzing functionalities provided are:
- Duplication
- Negation of numbers
- Duplication and negation
- Mutation of digits in both large range and fine differences
- Permutation of provided input

## Bonus Marks

# Future Work
Currently, the implementation of multiprocessing is hampered by the limits of Python3, that is asynchronous events are not handled robustly,
and the multiprocessing library makes interprocess communication more difficult than it should be. With the advent of Python4 and the asyncio library,
future work would include obsoleting the multiprocessing library in favour of asyncio for better performance and interprocess communication to prevent
racing between processes, locks of files (namely bad.txt), and graceful exiting of all processes.

Currently, there are no systems in place for intellegently checking code coverage for a more powerful input selection during fuzzing. An implementation 
of code coverage checking and evolutionary algorithms can help discover more powerful payloads more quickly.

Currently, there is no system for checking the time taken for each test to intellegently adapt the breadth of dumb fuzzing algorithms. If it can be 
observed that fuzzing is being completed too slowly due to a larger binary or slower computation, sample spaces should be reduced. Similarly, if 
fuzzing is completed quickly, sample spaces could be expanded.

Currently, CPU utilisation is not monitored and the limit of processes spawned at any moment is hardcoded. If it can be observed that CPU utilisation is 
not maximised, potentially due to processes blocking/waiting additional processes could be run to maximise performance.
