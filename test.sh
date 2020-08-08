#!/bin/bash

<<<<<<< HEAD
if [[ $# != 1 ]] || ! [[ "$1" =~ [a-zA-Z]+[0-9] ]]; then
    echo "Usage: ./test.sh <binary-name>"
    exit 1
fi

[[ -f bad.txt ]]  && rm bad.txt
[[ -f test.txt ]] && rm test.txt
./py/fuzzer.py $1 $1.txt

#[[ -f bad.txt ]] && cat bad.txt | binaries/$1
[[ -f test.txt ]] && cat test.txt | binaries/$1
[[ -f core ]] && rm core
=======
python py/fuzzer.py $1 $1.txt &
wait
sleep 1
cat bad.txt | binaries/$1
>>>>>>> ba80ed7450a0fb0b99e69fb2b22b876af163b725
