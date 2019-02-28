#include "hsm_enclave.h"

#include "edge_hsm_client_store.h"
#include "common.h"
#include "enc_u.h"

struct ENC_KEY_TAG
{
    HSM_CLIENT_KEY_INTERFACE intf;
    STRING_HANDLE key_file;
};
typedef struct ENC_KEY_TAG ENC_KEY;

static bool validate_input_param_buffer(const SIZED_BUFFER *sb, const char *name)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    bool result = true;

    if ((sb == NULL) || (sb->buffer == NULL))
    {
        LOG_ERROR("Invalid buffer for %s", name);
        result = false;
    }
    else if ((sb->size == 0) || (sb->size > INT_MAX))
    {
        LOG_ERROR("Parameter %s has invalid size %zu", name, sb->size);
        result = false;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

static bool validate_input_ciphertext_buffer(const SIZED_BUFFER *sb, unsigned char *version)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    bool result;

    if ((sb == NULL) || (sb->buffer == NULL))
    {
        LOG_ERROR("Invalid ciphertext buffer");
        result = false;
    }
    else if ((sb->size == 0) || (sb->size > INT_MAX))
    {
        LOG_ERROR("Ciphertext has invalid size %zu", sb->size);
        result = false;
    }
    else if (sb->buffer[0] != CIPHER_VERSION_V1)
    {
        LOG_ERROR("Unsupported encryption version %c", sb->buffer[0]);
        result = false;
    }
    else
    {
        *version = sb->buffer[0];
        result = true;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

static int enc_key_sign
(
    KEY_HANDLE key_handle,
    const unsigned char *data_to_be_signed,
    size_t data_to_be_signed_size,
    unsigned char **digest,
    size_t *digest_size
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    (void)key_handle;
    (void)data_to_be_signed;
    (void)data_to_be_signed_size;

    LOG_ERROR("Sign for encryption keys is not supported");
    if (digest != NULL)
    {
        *digest = NULL;
    }
    if (digest_size != NULL)
    {
        *digest_size = 0;
    }
    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, __FAILURE__);
    return __FAILURE__;
}

static int enc_key_derive_and_sign
(
    KEY_HANDLE key_handle,
    const unsigned char *data_to_be_signed,
    size_t data_to_be_signed_size,
    const unsigned char *identity,
    size_t identity_size,
    unsigned char **digest,
    size_t *digest_size
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    (void)key_handle;
    (void)data_to_be_signed;
    (void)data_to_be_signed_size;
    (void)identity;
    (void)identity_size;

    LOG_ERROR("Derive and sign for encryption keys is not supported");
    if (digest != NULL)
    {
        *digest = NULL;
    }
    if (digest_size != NULL)
    {
        *digest_size = 0;
    }
    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, __FAILURE__);
    return __FAILURE__;
}

static void bufprint(const unsigned char * buf, const size_t bufsz)
{
    for(size_t i = 0 ; i < bufsz ; i++)
        printf("%#x ", buf[i]);
	printf("\n");
}

static int enc_key_encrypt
(
    KEY_HANDLE key_handle,
    const SIZED_BUFFER *identity,
    const SIZED_BUFFER *plaintext,
    const SIZED_BUFFER *initialization_vector,
    SIZED_BUFFER *ciphertext
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    int result;

    if (ciphertext == NULL)
    {
        LOG_ERROR("Input ciphertext buffer is invalid");
        result = __FAILURE__;
    }
    else
    {
        ciphertext->buffer = NULL;
        ciphertext->size = 0;
        if ((!validate_input_param_buffer(plaintext, "plaintext")) ||
            (!validate_input_param_buffer(identity, "identity")) ||
            (!validate_input_param_buffer(initialization_vector, "initialization_vector")))
        {
            LOG_ERROR("Input data is invalid");
            result = __FAILURE__;
        }
        else
        {
            ENC_KEY *enc_key = (ENC_KEY*)key_handle;
            LOG_DEBUG("INSIDE: %s -- key file %s", __FUNCTION__, STRING_c_str(enc_key->key_file));
            ciphertext->size = plaintext->size + CIPHER_HEADER_V1_SIZE_BYTES;
            ciphertext->buffer = malloc(ciphertext->size);
            if (ciphertext->buffer == NULL)
            {
                LOG_ERROR("Could not allocate memory to encrypt data");
                result = __FAILURE__;
            }
            else if (ecall_Encrypt(
                hsm_enclave_get_instance(),
                &result,
                STRING_c_str(enc_key->key_file),
                plaintext->buffer,
                (int)plaintext->size,
                identity->buffer,
                (int)identity->size,
                initialization_vector->buffer,
                (int)initialization_vector->size,
                ciphertext->buffer,
                ciphertext->size) != OE_OK)
            {
                LOG_ERROR("Encrypt ecall failed");
                result = __FAILURE__;
            }
            else
            {
                LOG_DEBUG("INSIDE: %s -- ct follows:", __FUNCTION__);
                bufprint(ciphertext->buffer, ciphertext->size);
            }
        }
    }

    if (result != 0)
    {
        free(ciphertext->buffer);
        ciphertext->buffer = NULL;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

static int enc_key_decrypt
(
    KEY_HANDLE key_handle,
    const SIZED_BUFFER *identity,
    const SIZED_BUFFER *ciphertext,
    const SIZED_BUFFER *initialization_vector,
    SIZED_BUFFER *plaintext
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    int result;

    if (plaintext == NULL)
    {
        LOG_ERROR("Input plaintext buffer is invalid");
        result = __FAILURE__;
    }
    else
    {
        unsigned char version = 0;
        plaintext->buffer = NULL;
        plaintext->size = 0;
        if ((!validate_input_ciphertext_buffer(ciphertext, &version)) ||
            (!validate_input_param_buffer(identity, "identity")) ||
            (!validate_input_param_buffer(initialization_vector, "initialization_vector")))
        {
            LOG_ERROR("Input data is invalid");
            result = __FAILURE__;
        }
        else
        {
            LOG_DEBUG("INSIDE: %s -- ct follows:", __FUNCTION__);
            bufprint(ciphertext->buffer, ciphertext->size);

            ENC_KEY *enc_key = (ENC_KEY*)key_handle;
            LOG_DEBUG("INSIDE: %s -- key file %s", __FUNCTION__, STRING_c_str(enc_key->key_file));
            plaintext->size = ciphertext->size - CIPHER_HEADER_V1_SIZE_BYTES;
            plaintext->buffer = malloc(plaintext->size);
            if (plaintext->buffer == NULL) {
                LOG_ERROR("Could not allocate memory to decrypt data");
                result =  __FAILURE__;
            }
            else if (ecall_Decrypt(
                hsm_enclave_get_instance(),
                &result,
                STRING_c_str(enc_key->key_file),
                ciphertext->buffer,
                (int)ciphertext->size,
                identity->buffer,
                (int)identity->size,
                initialization_vector->buffer,
                (int)initialization_vector->size,
                plaintext->buffer,
                plaintext->size) != OE_OK)
            {
                LOG_ERROR("Decrypt ecall failed");
                result = __FAILURE__;
            }
            else
            {
                LOG_DEBUG("INSIDE: %s -- pt %s", __FUNCTION__, plaintext->buffer);
            }
        }
    }

    if (result != 0)
    {
        free(plaintext->buffer);
        plaintext->buffer = NULL;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

static void enc_key_destroy(KEY_HANDLE key_handle)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);

    ENC_KEY *enc_key = (ENC_KEY*)key_handle;

    if (enc_key != NULL)
    {
        if (enc_key->key_file != NULL)
        {
            STRING_delete(enc_key->key_file);
        }
        free(enc_key);
    }

    LOG_DEBUG("EXIT: %s", __FUNCTION__);
}

int verify_enclave_encryption_key(STRING_HANDLE key_file)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    int result;

    LOG_DEBUG("INSIDE: %s -- key file %s", __FUNCTION__, STRING_c_str(key_file));
    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        result = __FAILURE__;
    }
    else if (ecall_VerifyEncryptionKey(
        hsm_enclave_get_instance(),
        &result,
        STRING_c_str(key_file)) != OE_OK)
    {
        LOG_ERROR("VerifyEncryptionKey ecall failed");
        result = __FAILURE__;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

int generate_save_enclave_encryption_key(STRING_HANDLE key_file)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    int result;

    LOG_DEBUG("INSIDE: %s -- key file %s", __FUNCTION__, STRING_c_str(key_file));
    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        result = __FAILURE__;
    }
    else if (ecall_CreateEncryptionKey(
        hsm_enclave_get_instance(),
        &result,
        STRING_c_str(key_file)) != OE_OK)
    {
        LOG_ERROR("CreateEncryptionKey ecall failed");
        result = __FAILURE__;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

int delete_enclave_encryption_key(STRING_HANDLE key_file)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    int result;
    oe_result_t oe_res;

    LOG_DEBUG("INSIDE: %s -- key file %s", __FUNCTION__, STRING_c_str(key_file));
    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        result = __FAILURE__;
    }
    else if ((oe_res = ecall_DeleteEncryptionKey(
        hsm_enclave_get_instance(),
        &result,
        STRING_c_str(key_file))) != OE_OK)
    {
        LOG_ERROR("DeleteEncryptionKey ecall failed: %u", oe_res);
        result = __FAILURE__;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

KEY_HANDLE create_enclave_encryption_key(STRING_HANDLE key_file)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);

    int result = 0;
    LOG_DEBUG("INSIDE: %s -- key file %s", __FUNCTION__, STRING_c_str(key_file));

    ENC_KEY* enc_key;

    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        enc_key = NULL;
    }
    else
    {
        enc_key = (ENC_KEY*)malloc(sizeof(ENC_KEY));
        if (enc_key == NULL)
        {
            LOG_ERROR("Could not allocate memory for ENC_KEY");
        }
        else if ((enc_key->key_file = STRING_clone(key_file)) == NULL)
        {
            LOG_ERROR("Could not allocate memory for key file path");
            free(enc_key);
            enc_key = NULL;
        }
        else if (ecall_VerifyEncryptionKey(
            hsm_enclave_get_instance(),
            &result,
            STRING_c_str(enc_key->key_file)) != OE_OK || result != 0)
        {
            LOG_ERROR("VerifyEncryptionKey ecall failed");
            STRING_delete(enc_key->key_file);
            free(enc_key);
            enc_key = NULL;
        }
        else
        {
            enc_key->intf.hsm_client_key_sign = enc_key_sign;
            enc_key->intf.hsm_client_key_derive_and_sign = enc_key_derive_and_sign;
            enc_key->intf.hsm_client_key_encrypt = enc_key_encrypt;
            enc_key->intf.hsm_client_key_decrypt = enc_key_decrypt;
            enc_key->intf.hsm_client_key_destroy = enc_key_destroy;
        }
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return (KEY_HANDLE)enc_key;
}
