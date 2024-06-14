#!/bin/sh -ve
if [ -e queue-old ]; then
  rm -rf queue-old
fi
if [ -e output-old ]; then
  rm -rf output-old
fi

if [ -e queue ]; then
  mv queue queue-old
fi
if [ -e output ]; then
  mv output output-old
fi

chown shell:shell ./*
./mte-fuzz 7 4 0
