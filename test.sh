#!/bin/bash

python fuzzer.py $1 $1.txt &&
cat bad.txt | binaries/$1