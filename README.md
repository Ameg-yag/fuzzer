# Project Plan
## Description

You are to work in a team and write a fuzzer to look for vulnerabilities. There is intentionally a wide scope to this assignment and a lot of freedom for you to decide on your fuzzer capabilities. We will be providing support in course forums and have weekly check-ins to ensure you are staying on task.

The link to the binaries is here: https://cloudstor.aarnet.edu.au/plus/s/UFgbluP1AHPbV9Z

**We will be testing all the fuzzers against these binaries.**

This assessment is worth 20% of your final mark.

Register your group here: https://forms.gle/bLMoQARwM9GBtafe8 If you are not in a group by the end of week 6 talk to your tutor!

# Team formation

Postgraduates may elect to work individually or in a team (we suggest a team if you possibly can). Everyone else must work in a team.

Teams are of size 4. If there are an insufficient number of students in the class, there will be some groups of 5 formed (please consult course staff. You may team up with anyone currently enrolled in the course (it is fine to have teams of mixed undergraduates and postgraduates for example).

# Fuzzer (30 marks)

"Fuzzing or fuzz testing is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program. **The program is then monitored for exceptions** such as crashes, failing built-in code assertions, or potential memory leaks. This structure is specified, e.g., in a file format or protocol and distinguishes valid from invalid input. **An effective fuzzer generates semi-valid inputs that are "valid enough"** in that they are not directly rejected by the parser, but do create unexpected behaviors deeper in the program and are "invalid enough" to expose corner cases that have not been properly dealt with." ~wikipedia

For this project you will be required to implement a black box fuzzer, that given a binary containing a single vulnerability and a file containing one valid input to the binary, will need to find a valid input that causes an incorrect program state to occur (crash, invalid memory write, heap UAF, etc).

**All binaries will read in from stdin.**

The main goal of your fuzzer should be to touch as many codepaths as possible within the binary by either mutating the supplied valid input or generating completely new input (empty files, null bytes, really big files, etc).

Attempts to make a trivial fuzzer that simply return results from manual source code auditing or **relies extensively on other tooling** will be considered as **not completing the assignment**. This will receive a 0 grade.

You are permitted to do anything you wish (other than the above) to achieve the following ***functionality***.

The only real requirement is that you supply an executable file that takes in a single argument (the binary to fuzz), your executable should create a file called **bad.txt** which if passed into the binary as input causes the program to crash. Your fuzzer can add more files, or print debugging data to stdout as you wish. If you wish to create more files for processing, we recommend using the /tmp directory.

```
$ ls
fuzzer.exe binaryinput.txt binary
$ ./fuzzer.exe binary binaryinput.txt
Fuzzing this thing...
Found bad input.
$ ls
fuzzer.exe binary bad.txt binaryinput.txt
$ cat bad.txt | binary
Segmentation Fault
```

**The marks breakdown for the fuzzer is as follows ( / 30 marks)**

- 20 marks - for finding all vulnerabilities in the 10 provided binaries.
- 10 marks - for finding all vulnerabilities in the binaries that we do not provide.
- 6 marks - Something awesome . Something cool your fuzzer does.

Partial marks will be rewarded at the discretion of the marker if you miss some vulnerabilities.

## Assumptions

You can assume these facts when developing your fuzzer.

1. All binaries will have a vulnerability.
2. All binaries will function normally (return 0, not crash, no errors) when the relevant input.txt is passed into them.
3. All binaries will expect input in one of the following formats:
    - Plaintext (multiline)
    - json
    - xml
    - csv
4. The input. txt provided will be a valid form of one of these text formats.
5. You're fuzzer will have a maximum of 180 seconds per binary to find a vulnerability.
6. All binaries will be 32 bit linux ELF's.
7. All vulnerabilities will result in memory corruption.

## Technologies available

You can assume your programs will be run on an up to date 64-bit Linux system. The system will have the following programs installed:

- python
    - pwntools
- gdb
- gcc
    - C libraries

If you have a strong case to another required library / tool being available, please email the course staff and we can discuss adding it.
## Hints

Some hints if you are stuck on where to start.

    Try sending some known sample inputs (nothing, certain numbers, certain strings, etc)
    Try parsing the format of the input (normal text, json, etc) and send correctly formatted data with fuzzed fields.
    Try manipulating the sample input (bit flips, number replacement, etc)
    Try something awesome :D (There are no right answers)

## Something Awesome

The Something Awesome section is totally optional, and a bonus to the assignment. If you have something really cool you'd like to add to your fuzzer, let us know. **The bonus marks are totally up to the discretion of the marker.** This section is intentionally vague, we want you to think of cool ideas to add to your fuzzer.

**You cannot get more than 100% in this assignment.** The bonus 6 marks will count only for this assignment. If you get full marks, you don't get any bonus marks.

# Documentation (20 marks)

Your fuzzer design and functionality (around 1-2 pages)

This section should explain, in a readable manner:

- How your fuzzer works
- What kinds of bugs your fuzzer can find
- What improvements can be made to your fuzzer (Be honest. We won't dock marks for things you didn't implement. This shows reflection and understanding)
- If you attempts any bonus marks - How your fuzzer achieves these bonus marks.
- **It is insufficient if the document merely states "our fuzzer injects random values and finds bugs". We want details that show deep understanding.**

You do not have to follow any format, but this is the kind of information we expect to see in your documentation.

# Assignment Check-in (10 marks)

We want you to start early, so you don't get stressed last minute trying to implement your fuzzer. In week 7, you will need to submit a basic working version of your fuzzer **and** a half page description of your fuzzer, similar to the documentation description above. It does not have to the complete functionality of your fuzzer, but we want to make sure that you've started work on the major project.

For the check-in, we will only test your fuzzer against two binaries ( `csv1, json1` ). Like the final submission, we will supply a sample input so your fuzzer can manipulate our input.

We will run `./fuzzer program sampleinput.txt` to test your fuzzer.

The marks breakdown the midpoint check-in is:

    (6 marks) Find a vulnerability in the csv1 and json1 binaries.
    (4 marks) Half page description of your fuzzer functionality so far and the fuzzer design.
    Attempts to make a trivial fuzzer that simply return results from manual source code auditing or relies extensively on other tooling will be considered as not completing the assignment . This will receive a 0 grade .

# Submission

There is a 20% late penalty taken off the maximum mark you can achieve for each day the submission is late.

The midpoint submission is 17:59 Sunday July 19 (end of Week 7, Sydney time).

`give cs6447 midpoint writeup.md fuzzer.tar`

The fuzzer final submission is 17:59 Sunday August 9 (end of Week 10, Sydney time).

`give cs6447 fuzzer writeup.md fuzzer.tar`

# FAQ

- What language / libraries can I use to write my fuzzer?
    - You can use any language that you would like (C, C++, rust, python, etc), as long as it can be executed on a default install of linux. If it can't, talk to us and we can make some exceptions.
    - The bulk of the fuzzing logic must be **written by you**. However, you can use libraries to assist with encoding data into different formats (json, xml, etc), as well as running/debugging binaries.
