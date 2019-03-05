#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

include(oeedl_file)
oeedl_file(./enc.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

set(SGX_ENCLAVE enc)
set(TZ_UUID a511a7ab-a1a4-4ba6-bf2a-447c6c1fb116)

add_enclave(
    TARGET ${SGX_ENCLAVE}
    UUID ${TZ_UUID}
    SOURCES
        enc.c
        ${GEN}
    C_GEN ${C_GEN}
    LIBRARIES mbedcrypto_enc)

if(SGX)
    install(
        TARGETS ${SGX_ENCLAVE}
        LIBRARY DESTINATION ${CMAKE_INSTALL_BINDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR})

    install(
        FILES $<TARGET_FILE_DIR:enc>/enc.signed.dll
        DESTINATION ${CMAKE_INSTALL_BINDIR})
elseif(TZ)
    install(
        FILES ${OE_RUNTIME_OUTPUT_DIRECTORY}/${TZ_UUID}.ta
        DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
