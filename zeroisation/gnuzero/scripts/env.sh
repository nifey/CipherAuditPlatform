#!/bin/bash

usage() {
  echo -e "Usage:\n\t$0 /path/to/plugin.so"
}

if [ $# -ne 1 ]
then
  usage
else
  LIB=$(realpath $1)
  if [ -f $LIB -a -x $LIB ]
  then
    export PLUGIN=$LIB
    echo "Exported var PLUGIN=$PLUGIN"
  else
    echo -e "File $1 is not a file, does not exist or is not executable.\n\tRealpath: $LIB"
  fi
fi
