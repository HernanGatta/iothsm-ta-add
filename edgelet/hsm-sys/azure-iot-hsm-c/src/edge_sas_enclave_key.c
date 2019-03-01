#include "hsm_enclave.h"

#include "edge_hsm_client_store.h"
#include "common.h"
#include "enc_u.h"

struct SAS_KEY_TAG
{
    HSM_CLIENT_KEY_INTERFACE intf;
    STRING_HANDLE key_file;
};
typedef struct SAS_KEY_TAG SAS_KEY;

static int sas_key_sign
(
    KEY_HANDLE key_handle,
    const unsigned char* data_to_be_signed,
    size_t data_to_be_signed_size,
    unsigned char** digest,
    size_t* digest_size
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);

    int result;
    SAS_KEY *sas_key = (SAS_KEY*)key_handle;

    if (sas_key == NULL)
    {
        LOG_ERROR("Invalid key handle");
        result = __FAILURE__;
    }
    else
    {
        *digest_size = MD_OUTPUT_SIZE;
        *digest = malloc(*digest_size);
        if (*digest == NULL)
        {
            LOG_ERROR("Failed to allocate digest buffer");
            result = __FAILURE__;
        }
        else if (ecall_Sign(
            hsm_enclave_get_instance(),
            &result,
            STRING_c_str(sas_key->key_file),
            data_to_be_signed,
            data_to_be_signed_size,
            *digest,
            *digest_size) != OE_OK)
        {
            LOG_ERROR("Sign ecall failed");
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
    }

    if (result != 0 && *digest != NULL)
    {
        free(*digest);

        *digest = NULL;
        *digest_size = 0;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

static int sas_key_derive_and_sign
(
    KEY_HANDLE key_handle,
    const unsigned char* data_to_be_signed,
    size_t data_to_be_signed_size,
    const unsigned char* identity,
    size_t identity_size,
    unsigned char** digest,
    size_t* digest_size
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);

    int result;
    SAS_KEY* sas_key = (SAS_KEY*)key_handle;

    *digest_size = MD_OUTPUT_SIZE;
    *digest = malloc(*digest_size);
    if (*digest == NULL)
    {
        LOG_ERROR("Failed to allocate digest buffer");
        result = __FAILURE__;
    }
    else if (ecall_DeriveAndSign(
        hsm_enclave_get_instance(),
        &result,
        STRING_c_str(sas_key->key_file),
        identity,
        identity_size,
        data_to_be_signed,
        data_to_be_signed_size,
        *digest,
        *digest_size) != OE_OK)
    {
        LOG_ERROR("DeriveAndSign ecall failed");
        result = __FAILURE__;
    }
    else
    {
        result = 0;
    }

    if (result != 0 && *digest != NULL)
    {
        free(*digest);

        *digest = NULL;
        *digest_size = 0;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

static int sas_key_encrypt(KEY_HANDLE key_handle,
                            const SIZED_BUFFER *identity,
                            const SIZED_BUFFER *plaintext,
                            const SIZED_BUFFER *initialization_vector,
                            SIZED_BUFFER *ciphertext)
{
    (void)key_handle;
    (void)identity;
    (void)plaintext;
    (void)initialization_vector;

    LOG_ERROR("Shared access key encrypt operation not supported");
    ciphertext->buffer = NULL;
    ciphertext->size = 0;
    return 1;
}

static int sas_key_decrypt(KEY_HANDLE key_handle,
                            const SIZED_BUFFER *identity,
                            const SIZED_BUFFER *ciphertext,
                            const SIZED_BUFFER *initialization_vector,
                            SIZED_BUFFER *plaintext)
{
    (void)key_handle;
    (void)identity;
    (void)ciphertext;
    (void)initialization_vector;

    LOG_ERROR("Shared access key decrypt operation not supported");
    plaintext->buffer = NULL;
    plaintext->size = 0;
    return 1;
}

static void sas_key_destroy(KEY_HANDLE key_handle)
{
    SAS_KEY *sas_key = (SAS_KEY*)key_handle;
    if (sas_key != NULL)
    {
        if (sas_key->key_file != NULL)
        {
            STRING_delete(sas_key->key_file);
        }
        free(sas_key);
    }
}

int verify_enclave_sas_key(STRING_HANDLE key_file)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    int result;

    LOG_DEBUG("INSIDE: %s -- key file %s", __FUNCTION__, STRING_c_str(key_file));
    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        result = __FAILURE__;
    }
    else if (ecall_VerifySasKey(
        hsm_enclave_get_instance(),
        &result,
        STRING_c_str(key_file)) != OE_OK)
    {
        LOG_ERROR("VerifySasKey ecall failed");
        result = __FAILURE__;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

int import_enclave_sas_key
(
    STRING_HANDLE key_file,
    const unsigned char* key,
    size_t key_size
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);

    int result;

    LOG_DEBUG("INSIDE: %s -- key file %s", __FUNCTION__, STRING_c_str(key_file));
    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        result = __FAILURE__;
    }
    else if (ecall_ImportSasKey(
        hsm_enclave_get_instance(),
        &result,
        STRING_c_str(key_file),
        key,
        key_size) != OE_OK)
    {
        LOG_ERROR("ImportSasKey ecall failed");
        result = __FAILURE__;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

int delete_enclave_sas_key(STRING_HANDLE key_file)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);

    int result;

    LOG_DEBUG("INSIDE: %s -- key file %s", __FUNCTION__, STRING_c_str(key_file));
    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        result = __FAILURE__;
    }
    else if (ecall_DeleteSasKey(
        hsm_enclave_get_instance(),
        &result,
        STRING_c_str(key_file)) != OE_OK)
    {
        LOG_ERROR("DeleteSasKey ecall failed");
        result = __FAILURE__;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

KEY_HANDLE create_enclave_sas_key(STRING_HANDLE key_file)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);

    int result = 0;

    LOG_DEBUG("INSIDE: %s -- key file %s", __FUNCTION__, STRING_c_str(key_file));

    SAS_KEY* sas_key;
    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        sas_key = NULL;
    }
    else
    {
        sas_key = (SAS_KEY*)malloc(sizeof(SAS_KEY));
        if (sas_key == NULL)
        {
            LOG_ERROR("Could not allocate memory for SAS_KEY");
        }
        else if ((sas_key->key_file = STRING_clone(key_file)) == NULL)
        {
            LOG_ERROR("Could not allocate memory for key file path");
            free(sas_key);
            sas_key = NULL;
        }
        else if (ecall_VerifySasKey(
            hsm_enclave_get_instance(),
            &result,
            STRING_c_str(sas_key->key_file)) != OE_OK || result != 0)
        {
            LOG_ERROR("VerifySasKey ecall failed");
            STRING_delete(sas_key->key_file);
            free(sas_key);
            sas_key = NULL;
        }
        else
        {
            sas_key->intf.hsm_client_key_sign = sas_key_sign;
            sas_key->intf.hsm_client_key_derive_and_sign = sas_key_derive_and_sign;
            sas_key->intf.hsm_client_key_encrypt = sas_key_encrypt;
            sas_key->intf.hsm_client_key_decrypt = sas_key_decrypt;
            sas_key->intf.hsm_client_key_destroy = sas_key_destroy;
        }
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return (KEY_HANDLE)sas_key;
}
