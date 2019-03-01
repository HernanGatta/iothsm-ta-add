#ifndef EDGE_SAS_ENCLAVE_KEY_H
#define EDGE_SAS_ENCLAVE_KEY_H

#ifdef __cplusplus
#include <cstdbool>
#include <cstddef>
extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#endif

#include "azure_c_shared_utility/umock_c_prod.h"
#include "hsm_key_interface.h"

MOCKABLE_FUNCTION(, KEY_HANDLE, create_enclave_sas_key, STRING_HANDLE, key_file);
MOCKABLE_FUNCTION(, int, import_enclave_sas_key, STRING_HANDLE, key_file, const unsigned char*, key, size_t, key_size);
MOCKABLE_FUNCTION(, int, verify_enclave_sas_key, STRING_HANDLE, key_file);
MOCKABLE_FUNCTION(, int, delete_enclave_sas_key, STRING_HANDLE, key_file);

#ifdef __cplusplus
}
#endif

#endif  //EDGE_SAS_ENCLAVE_KEY_H
