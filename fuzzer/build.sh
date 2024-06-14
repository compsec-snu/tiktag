#!/bin/bash -ve

export ADB_PATH=adb

export FILE="mte-fuzz"
make clean && make

$ADB_PATH -s $1 push ./$FILE /data/local/tmp/fuzzer/
$ADB_PATH -s $1 push ./run-fuzzer.sh /data/local/tmp/fuzzer/

