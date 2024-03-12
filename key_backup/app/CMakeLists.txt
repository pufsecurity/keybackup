cmake_minimum_required(VERSION 3.19)
#add_executable(clearKey)
#add_executable(hmacKey)
#add_executable(encryptData)
#add_executable(generateKey)
#add_executable(client)
#add_executable(server)
#add_executable(pure)

target_sources(clearKey
    PRIVATE
    clearKey.c
)

target_sources(hmacKey
    PRIVATE
    hmacKey.c
)

target_sources(encryptData
    PRIVATE
    encryptData.c
)

target_sources(generateKey
    PRIVATE
    generateKey.c
)

target_sources(client
    PRIVATE
    client.c
)

target_sources(server
    PRIVATE
    server.c
)

#target_sources(pure
#    PRIVATE
#    pure.c
#)

include(cmake/import_pufse.cmake)
target_link_libraries(clearKey
    PRIVATE
        pufse_interface   
        -L./
        -lcore
        pufselib
        ${LIBUDEV}
        -pthread
)

target_link_libraries(hmacKey
    PRIVATE
        pufse_interface   
        -L./
        -lcore
        pufselib
        ${LIBUDEV}
        -pthread
)

target_link_libraries(encryptData
    PRIVATE
        pufse_interface   
        -L./
        -lcore
        pufselib
        ${LIBUDEV}
        -pthread
)

target_link_libraries(generateKey
    PRIVATE
        pufse_interface   
		-L${PROJECT_SOURCE_DIR}/app/openssl/lib 
		-lssl
		-lcrypto
		#libssl.a
		#libcrypto.a
		-ldl
        -L./
        -lcore
        pufselib
        ${LIBUDEV}
        -pthread
)

target_link_libraries(client
    PRIVATE
        pufse_interface   
		-L${PROJECT_SOURCE_DIR}/app/openssl/lib 
		-lssl
		-lcrypto
		#libssl.a
		#libcrypto.a
		-ldl
        -L./
        -lcore
        pufselib
        ${LIBUDEV}
        -pthread
)

target_link_libraries(server
    PRIVATE
        pufse_interface   
		-L${PROJECT_SOURCE_DIR}/app/openssl/lib 
		-lssl
		-lcrypto
		#libssl.a
		#libcrypto.a
		-ldl
        -L./
        -lcore
        pufselib
        ${LIBUDEV}
        -pthread
)
target_include_directories(clearKey
    PRIVATE
        pufse_interface   
        ./openssl/include
        ../../pufs_common
        ../../test
)

target_include_directories(hmacKey
    PRIVATE
        pufse_interface   
        ./openssl/include
        ../../pufs_common
        ../../test
)

target_include_directories(encryptData
    PRIVATE
        pufse_interface   
        ./openssl/include
        ../../test
)

target_include_directories(generateKey
    PRIVATE
        pufse_interface   
        ./openssl/include
        ../../test
)

target_include_directories(client
    PRIVATE
        pufse_interface   
        ./openssl/include
        ../../test
        ${PUFS_MEMORY_MAP_PATH}
)

target_include_directories(server
    PRIVATE
        pufse_interface   
        ./openssl/include
        ../../test
        ${PUFS_MEMORY_MAP_PATH}
)


#link_libraries(${PROJECT_SOURCE_DIR}/app/openssl/libssl.so)
#link_libraries(${PROJECT_SOURCE_DIR}/app/openssl/libcrypto.so)

# Always release template version
#add_test_file(${CMAKE_CURRENT_LIST_DIR}/clearKey.c)
#add_test_file(${CMAKE_CURRENT_LIST_DIR}/hmacKey.c)
#add_test_file(${CMAKE_CURRENT_LIST_DIR}/encryptData.c)
#add_test_file(${CMAKE_CURRENT_LIST_DIR}/generateKey.c)
#add_test_file(${CMAKE_CURRENT_LIST_DIR}/client.c)
#add_test_file(${CMAKE_CURRENT_LIST_DIR}/server.c)
#add_test_file(${CMAKE_CURRENT_LIST_DIR}/pure.c)
