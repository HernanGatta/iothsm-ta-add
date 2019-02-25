#ifndef HSM_ENCLAVE_KEY_H
#define HSM_ENCLAVE_KEY_H

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

MOCKABLE_FUNCTION(, KEY_HANDLE, create_enclave_encryption_key, STRING_HANDLE, key_file);
MOCKABLE_FUNCTION(, int, generate_save_enclave_encryption_key, STRING_HANDLE, key_file);
MOCKABLE_FUNCTION(, int, verify_enclave_encryption_key, STRING_HANDLE, key_file);
MOCKABLE_FUNCTION(, int, delete_enclave_encryption_key, STRING_HANDLE, key_file);

#ifdef __cplusplus
}
#endif

#endif  //HSM_ENCLAVE_KEY_H
