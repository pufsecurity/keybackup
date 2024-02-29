#!/bin/bash

TAR_NAME=openssl_root.tar.gz

if [[ "$1" == "decomp" ]]; then
    tar zxvf ${TAR_NAME}    
    exit;
fi

LIB_PATH=${PWD}/openssl-1.1.1k/openssl_root/lib
LIB_NAME=libssl.so
BIN_PATH=${PWD}/openssl-1.1.1k/openssl_root/bin

if [ -e "${LIB_PATH}/${LIB_NAME}" ]; then
    export LD_LIBRARY_PATH=${LIB_PATH}:${LD_LIBRARY_PATH}
    export PATH=${BIN_PATH}:${PATH}
    echo LD_LIBRARY_PATH=${LD_LIBRARY_PATH}
    echo PATH=${PATH}
else
    echo "${LIB_PATH}/${LIB_NAME} does not exist."
fi

