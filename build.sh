#!/bin/bash

ROOT=${PWD}
PUFSE_PATH=${PWD}/lib/pufse-host-lib/pufse
HID_API_PATH=${PWD}/lib/pufse-host-lib
UDEV_PATH=${PWD}/lib/libudev
LIBUDEV="-L${UDEV_PATH} -ludev"

if [[ $1 == "openssl_arm" ]]; then
    cd lib/openssl
    if [ ! -f "openssl-1.1.1k.tar.gz" ]; then 
        ./download.sh
    fi
    if [ -f "openssl-1.1.1k.tar.gz" ]; then 
        ./decompress.sh
    fi
    if [ -d "openssl-1.1.1k" ]; then 
        ./build.sh all
        ./build.sh install
    fi
elif [[ $1 == "keybackup_arm" ]]; then
    if [ -d "lib/pufse-host-lib/pufse/key_backup" ]; then 
        echo key_backup exist
    else
        echo Create symbolic link key_backup
        ln -s ${PWD}/key_backup lib/pufse-host-lib/pufse/key_backup
    fi
    rm ${PWD}/key_backup/app/openssl
    ln -s ${PWD}/lib/openssl/openssl-1.1.1k/openssl_root ${PWD}/key_backup/app/openssl
    cd lib/pufse-host-lib/pufse/key_backup
    cmake -S . -B build -DPUFSE_PATH=${PUFSE_PATH} -DHID_API_PATH=${HID_API_PATH} -DLIBUDEV="${LIBUDEV}" -DCMAKE_TOOLCHAIN_FILE="${ROOT}/key_backup/cmake/arm-linux-gnueabihf.cmake"
    cp app/*.sh app/ca_key/ca.* app/scp_auto.expect app/keybackup.conf app/data.txt ${ROOT}/lib/pufse-host-lib/build/pufse/src/libpufse.so build
    cmake --build build
fi
