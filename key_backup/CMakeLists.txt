cmake_minimum_required(VERSION 3.19)
project(key_backup C)

# Assume pufcc-test is put under pufcc in default
if(NOT DEFINED ENV{PUFSE_PATH})
    set(PUFSE_PATH ${PROJECT_SOURCE_DIR}/.. CACHE STRING "Path to PUFse library repository.")
endif()
if(NOT DEFINED ENV{HID_API_PATH})
    set(HID_API_PATH ${PROJECT_SOURCE_DIR}/../.. CACHE STRING "Path to PUFse library repository.")
endif()

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    include(cmake/config.cmake)
endif()

#include(${PUFCC_PATH}/pufcc-test/cmake/config.cmake)
#include(${PUFCC_PATH}/pufcc-test/cmake/version.cmake)
#include(${PUFCC_PATH}/pufcc-test/cmake/release_macros.cmake)

add_library(pufse_interface INTERFACE)
# fixme, see temporary workaround below
target_include_directories(pufse_interface
    INTERFACE
        ${PUFSE_PATH}/inc
	${PUFSE_PATH}/hal
	${HID_API_PATH}/hidapi/hidapi
)

add_library(core SHARED  ./app/libcore.c)
target_link_libraries(core
    PRIVATE
    	pufse_interface
        ${CCFLAG}
)

target_include_directories(core
    PRIVATE
        ./app/openssl/include
)

# add target for pufcc-test artiface(executable or shared library)
if (PUFS_TEST_TYPE STREQUAL "Robot")
    add_library(${PROJECT_NAME}_exec SHARED)
    set_target_properties(${PROJECT_NAME}_exec PROPERTIES OUTPUT_NAME "${PROJECT_NAME}lib")
else()
    add_executable(clearKey)
    add_executable(hmacKey)
    add_executable(encryptData)
    add_executable(generateKey)
    add_executable(client)
    add_executable(server)
    #add_executable(pure)
endif()

# add application layer
add_subdirectory(app)

include(cmake/import_pufse.cmake)

