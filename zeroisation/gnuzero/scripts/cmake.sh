#!/bin/bash

usage(){
    echo "$0 <GCC_VERSION> [GENERATOR=Ninja]"
}

set -x

if [ ! -d "./build" ]
then
    mkdir "./build"
fi

if [ $# -eq 1 ]
then
    GCC_VERSION=$1
    GENERATOR="Ninja"
elif [ $# -eq 2 ]
then
    GCC_VERSION=$1
    GENERATOR=$2
else
    usage
    exit 1
fi

cd ./build
cmake --log-level=DEBUG -DGCC_VERSION=$GCC_VERSION -G $GENERATOR ../
