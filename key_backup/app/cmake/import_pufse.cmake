cmake_minimum_required(VERSION 3.18.2)

# Assume pufse has already been compiled and put under ../build/src
find_library(pufselib_path NAMES "pufse"
                PATHS ${HID_API_PATH}/build/pufse/src NO_DEFAULT_PATH NO_CACHE)

if (pufselib_path MATCHES ".*\.so$")
    add_library(pufselib SHARED IMPORTED)
else()
    add_library(pufselib STATIC IMPORTED)
endif()

set_property(TARGET pufselib PROPERTY IMPORTED_LOCATION ${pufselib_path})