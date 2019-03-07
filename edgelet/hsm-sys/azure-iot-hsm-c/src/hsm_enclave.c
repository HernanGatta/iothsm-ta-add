#include "azure_c_shared_utility/macro_utils.h"

#include "hsm_log.h"
#include "hsm_enclave.h"

#include "enc_u.h"

#if defined(_ARM_) || defined(_M_ARM) || defined(__arm__) || defined(__thumb__) || defined(__aarch64__) || defined(OE_SIMULATE_OPTEE)
# define ENCLAVE_NAME "a511a7ab-a1a4-4ba6-bf2a-447c6c1fb116"
#else
# define ENCLAVE_NAME "enc"
#endif

static oe_enclave_t* g_hsm_enclave = NULL;

oe_enclave_t* hsm_enclave_get_instance(void)
{
    if (g_hsm_enclave == NULL)
    {
        if (oe_create_enc_enclave(
            ENCLAVE_NAME,
            OE_ENCLAVE_TYPE_DEFAULT,
            0,
            NULL,
            0,
            &g_hsm_enclave) != OE_OK)
        {
            LOG_ERROR("Could not create HSM enclave");
        }
        else
        {
            LOG_DEBUG("Created HSM enclave");
        }
    }

    return g_hsm_enclave;
}

int hsm_enclave_destroy(void)
{
    int result;

    if (g_hsm_enclave == NULL)
    {
        LOG_ERROR("Attempted to destroy HSM enclave, but it has not been created");
        result = __FAILURE__;
    }
    else if (oe_terminate_enclave(g_hsm_enclave) != OE_OK)
    {
        LOG_ERROR("Could not terminate HSM enclave");
        result = __FAILURE__;
    }
    else
    {
        LOG_DEBUG("Terminated HSM enclave");
        
        result = 0;
    }

    return result;
}
