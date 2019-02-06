#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

include(oeedl_file)
oeedl_file(./enc.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

add_enclave(
    TARGET enc
    UUID a511a7ab-a1a4-4ba6-bf2a-447c6c1fb116
    SOURCES
        enc.c
        ${GEN}
    C_GEN ${C_GEN})
