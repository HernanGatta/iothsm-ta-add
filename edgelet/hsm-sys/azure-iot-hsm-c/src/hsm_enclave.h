#ifndef HSM_ENCLAVE_H
#define HSM_ENCLAVE_H

#include <openenclave/host.h>

oe_enclave_t* hsm_enclave_get_instance(void);
int hsm_enclave_destroy(void);

#endif //HSM_ENCLAVE_H
