#!/bin/bash
/usr/bin/make "PIN_ROOT=$(find .. -maxdepth 1 -type d -regextype sed -regex ".*pin.*" -print -quit)" $@
cd parsers
/usr/bin/make
cd ..
