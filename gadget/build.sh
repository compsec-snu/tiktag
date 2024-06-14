#!/bin/bash -e

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <serial_nubmer>" >&2
  exit 1
fi

export TIMER=0 # Virtual counter
# export TIMER=1 # Cycle counter

make clean
make

adb  -s $1 push ./poc /data/local/tmp/poc
