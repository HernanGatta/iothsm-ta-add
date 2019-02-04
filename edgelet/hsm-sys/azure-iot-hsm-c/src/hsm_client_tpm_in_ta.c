// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "azure_c_shared_utility/gballoc.h"
#include "hsm_client_data.h"
#include "hsm_client_store.h"
#include "hsm_log.h"
#include "hsm_constants.h"

#include "enc_u.h"
#include "common.h"

struct EDGE_TPM_TAG
{
	oe_enclave_t* enclave;
};
typedef struct EDGE_TPM_TAG EDGE_TPM;

static bool g_is_tpm_initialized = false;

static HSM_CLIENT_HANDLE hsm_client_tpm_ta_create(void)
{
    HSM_CLIENT_HANDLE result;
    EDGE_TPM* edge_tpm;

    if (!g_is_tpm_initialized)
    {
        LOG_ERROR("hsm_client_tpm_init not called");
        result = NULL;
    }
    else if ((edge_tpm = (EDGE_TPM*)calloc(1, sizeof(EDGE_TPM))) == NULL)
    {
        LOG_ERROR("Could not allocate memory for TPM client");
        result = NULL;
    }
	else if ((oe_create_enc_enclave("enc", OE_ENCLAVE_TYPE_DEFAULT, 0, NULL, 0, &edge_tpm->enclave)) != OE_OK)
	{
		LOG_ERROR("Could not create enclave");
		free(edge_tpm);
		result = NULL;
	}
    else
    {
        result = (HSM_CLIENT_HANDLE)edge_tpm;
    }
    return result;
}

static void hsm_client_tpm_ta_destroy(HSM_CLIENT_HANDLE handle)
{
    if (!g_is_tpm_initialized)
    {
        LOG_ERROR("hsm_client_tpm_init not called");
    }
    else if (handle != NULL)
    {
        EDGE_TPM *edge_tpm = (EDGE_TPM*)handle;

		if (oe_terminate_enclave(edge_tpm->enclave) != OE_OK)
		{
			LOG_ERROR("Could not terminate enclave");
		}

        free(edge_tpm);
    }
}

static int hsm_client_tpm_ta_activate_identity_key
(
    HSM_CLIENT_HANDLE handle,
    const unsigned char* key,
    size_t key_len
)
{
	int result = 0;
	EDGE_TPM *edge_tpm = (EDGE_TPM*) handle;

    if (!g_is_tpm_initialized)
    {
        LOG_ERROR("hsm_client_tpm_init not called");
        result = __FAILURE__;
    }
    else if (handle == NULL)
    {
        LOG_ERROR("Invalid handle value specified");
        result = __FAILURE__;
    }
    else if (key == NULL)
    {
        LOG_ERROR("Invalid key specified");
        result = __FAILURE__;
    }
    else if (key_len == 0)
    {
        LOG_ERROR("Key len length cannot be 0");
        result = __FAILURE__;
    }
	else if (ecall_TaSetSigningKey(
        edge_tpm->enclave,
        &result,
        key,
        key_len) != OE_OK || result != 0)
	{
		LOG_ERROR("TaSetSigningKey ecall failed");
		result = __FAILURE__;
	}

    return result;
}

static int ek_srk_unsupported
(
    HSM_CLIENT_HANDLE handle,
    unsigned char** key,
    size_t* key_len
)
{
    int result = 0;

    if (key == NULL)
    {
        LOG_ERROR("Invalid key specified");
        result = __FAILURE__;
    }
    else
    {
        *key = NULL;
    }
    if (key_len == NULL)
    {
        LOG_ERROR("Invalid key len specified");
        result = __FAILURE__;
    }
    else
    {
        *key_len = 0;
    }
    if (result == 0)
    {
        if (!g_is_tpm_initialized)
        {
            LOG_ERROR("hsm_client_tpm_init not called");
            result = __FAILURE__;
        }
        else if (handle == NULL)
        {
            LOG_ERROR("Invalid handle value specified");
            result = __FAILURE__;
        }
        else
        {
            LOG_ERROR("API unsupported");
            result = __FAILURE__;
        }
    }
    return result;
}

static int hsm_client_tpm_ta_get_ek
(
    HSM_CLIENT_HANDLE handle,
    unsigned char** key,
    size_t* key_len
)
{
    return ek_srk_unsupported(handle, key, key_len);
}

static int hsm_client_tpm_ta_get_srk
(
    HSM_CLIENT_HANDLE handle,
    unsigned char** key,
    size_t* key_len
)
{
    return ek_srk_unsupported(handle, key, key_len);
}

static int hsm_client_tpm_ta_sign_with_identity
(
    HSM_CLIENT_HANDLE handle,
    const unsigned char* data_to_be_signed,
    size_t data_to_be_signed_size,
    unsigned char** digest,
    size_t* digest_size
)
{
	int result;
	EDGE_TPM* edge_tpm = (EDGE_TPM*)handle;

	if (handle == NULL ||
		data_to_be_signed == NULL ||
		digest == NULL ||
		digest_size == NULL)
	{
		LOG_ERROR("Invalid argument to hsm_client_tpm_ta_sign_with_identity");
		return __FAILURE__;
	}

	*digest_size = MD_OUTPUT_SIZE;
	*digest = malloc(*digest_size);
	if (*digest == NULL) {
		LOG_ERROR("Failed to allocate digest buffer");
		return __FAILURE__;
	}
	
	if (ecall_TaSignData(
        edge_tpm->enclave,
        &result,
        data_to_be_signed,
        data_to_be_signed_size,
        *digest,
        *digest_size) != OE_OK || result != 0)
	{
		LOG_ERROR("TaSignData ecall failed");
		return __FAILURE__;
	}

	return 0;
}

static int hsm_client_tpm_ta_derive_and_sign_with_identity
(
    HSM_CLIENT_HANDLE handle,
    const unsigned char* data_to_be_signed,
    size_t data_to_be_signed_size,
    const unsigned char* identity,
    size_t identity_size,
    unsigned char** digest,
    size_t* digest_size
)
{
	int result;
	EDGE_TPM* edge_tpm = (EDGE_TPM*)handle;

	if (handle == NULL ||
		data_to_be_signed == NULL ||
		identity == NULL ||
		digest == NULL ||
		digest_size == NULL)
	{
		LOG_ERROR("Invalid argument to hsm_client_tpm_ta_derive_and_sign_with_identity");
		return __FAILURE__;
	}

	*digest_size = MD_OUTPUT_SIZE;
	*digest = malloc(*digest_size);
	if (*digest == NULL) {
		LOG_ERROR("Failed to allocate digest buffer");
		return __FAILURE__;
	}

	if (ecall_TaDeriveAndSignData(
        edge_tpm->enclave,
        &result,
        identity,
        identity_size,
        data_to_be_signed,
        data_to_be_signed_size,
        *digest,
        *digest_size) != OE_OK || result != 0)
	{
		LOG_ERROR("TaDeriveAndSignData ecall failed");
		return __FAILURE__;
	}

	return 0;
}

static void hsm_client_tpm_ta_free_buffer(void *buffer)
{
    if (buffer != NULL)
    {
        free(buffer);
    }
}

int hsm_client_tpm_ta_init(void)
{
    return 0;
}

void hsm_client_tpm_ta_deinit(void)
{
}

static const HSM_CLIENT_TPM_INTERFACE ta_tpm_interface =
{
    hsm_client_tpm_ta_create,
    hsm_client_tpm_ta_destroy,
    hsm_client_tpm_ta_activate_identity_key,
    hsm_client_tpm_ta_get_ek,
    hsm_client_tpm_ta_get_srk,
    hsm_client_tpm_ta_sign_with_identity,
    hsm_client_tpm_ta_derive_and_sign_with_identity,
    hsm_client_tpm_ta_free_buffer
};

const HSM_CLIENT_TPM_INTERFACE* hsm_client_tpm_ta_interface()
{
    return &ta_tpm_interface;
}
