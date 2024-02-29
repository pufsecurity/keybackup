cmake_minimum_required(VERSION 3.18.2)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_EXTRA_C_FLAGS} -m32 -Wall -Werror -Wextra -pedantic -pedantic-errors -Wstrict-prototypes")

# CMAKE_BUILD_TYPE should be empty if not set by user
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type: [Debug, Release, RelWithDebInfo, MinSizeRel]" FORCE)
endif()
