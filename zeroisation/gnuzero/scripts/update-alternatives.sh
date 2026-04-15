#!/bin/bash
usage() {
    echo "$0 {trunk,custom,dev}"
}

set -x

if [ $# -ne 1 ]
then
    usage
    exit 1 
fi

if [ $1 = "trunk" ]
then
    sudo update-alternatives --set gcc $HOME/.local/bin/gcc_trunk
    sudo update-alternatives --set g++ $HOME/.local/bin/g++_trunk
elif [ $1 = "custom" ]
then
    sudo update-alternatives --set gcc $HOME/.local/bin/gcc_modified
    sudo update-alternatives --set g++ $HOME/.local/bin/g++_modified
elif [ $1 = "dev" ]
then
    sudo update-alternatives --set gcc $HOME/.local/bin/gcc_dev
    sudo update-alternatives --set g++ $HOME/.local/bin/g++_dev
else
    usage
    exit 1
fi
