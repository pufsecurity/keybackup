#!/bin/bash

package_name=openssl
package_version=1.1.1k
package_path=${package_name}-${package_version}
TAR_PATH=${package_path}/${package_name}_root
TAR_NAME=${package_name}_root.tar.gz

#COMPILE_PREFIX=${PWD}/../toolchain/gcc-arm-10.2-2020.11-x86_64-arm-none-linux-gnueabihf/bin/arm-none-linux-gnueabihf-
COMPILE_PREFIX=arm-linux-gnueabihf-
PREFIX=${PWD}/${package_path}/${package_name}_root

if [[ "$1" == "export" ]]; then
    COMPILE_PATH=${PWD}/../toolchain/gcc-arm-10.2-2020.11-x86_64-arm-none-linux-gnueabihf/bin
    export PATH=${COMPILE_PATH}:$PATH
    echo export PATH=$PATH
    echo return
    return
fi

cd ${package_path}

if [[ "$1" == "all" ]]; then
    make distclean
    ./Configure linux-generic32 --cross-compile-prefix=${COMPILE_PREFIX} -fPIC -shared --prefix=${PREFIX}
elif [[ "$1" == "x86_32" ]]; then
    #make distclean
    ./Configure linux-generic32 -m32 -fPIC -shared --prefix=${PREFIX}_x86_32
elif [[ "$1" == "x86_64" ]]; then
    make distclean
    ./Configure linux-generic32 -fPIC -shared --prefix=${PREFIX}_x86_64
fi

make

if [[ "$1" == "install" ]]; then
    make install
    cd ..
    #tar zcvf ${TAR_NAME} ${TAR_PATH}
fi


