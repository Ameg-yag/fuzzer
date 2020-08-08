#!/bin/bash

python3 py/fuzzer.py $1 $1.txt &
wait
sleep 1
cat bad.txt | binaries/$1