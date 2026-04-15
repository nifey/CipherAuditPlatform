#!/bin/bash

usage() {
    echo "$0 {trunk,custom,dev} [PATH_TO_GCC_SRC=$HOME/soft/gcc/src/gcc]"
}

weird() {
    echo "GCC repository is probably not on the right branch for $1"
}

set -x

if [ $# -lt 1 ]
then
    usage
    exit 1
fi

if [ $2 ]
then
    GCC_REPO=$2
else
    GCC_REPO=$HOME/soft/gcc/src/gcc
fi

BASE_VER=$(cat $GCC_REPO/BASE-VER)
DEST=$HOME/.local/lib/gcc/x86_64-pc-linux-gnu/$BASE_VER/include/analyzer

if [ $1 = "trunk" -a $BASE_VER = "13.0.1"]
then
    if [ ! -d $DEST ]
    then
        mkdir $DEST
    fi
    cp $GCC_REPO/analyzer/*.h $DEST
elif [ $1 = "custom" -a $BASE_VER = "13.0.1_custom" ]
then
    if [ ! -d $DEST ]
    then
        mkdir $DEST
    fi
    cp $GCC_REPO/analyzer/*.h $DEST
elif [ $1 = "dev" -a $BASE_VER = "13.0.1_custom_dev" ]
then
    if [ ! -d $DEST ]
    then
        mkdir $DEST
    fi
    cp $GCC_REPO/analyzer/*.h $DEST
else
    usage
    weird $1
    exit 1
fi
