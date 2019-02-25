#include <openenclave/host.h>

#include "edge_hsm_client_store.h"
#include "common.h"
#include "enc_u.h"

static oe_enclave_t *enc;

struct ENC_KEY_TAG
{
    HSM_CLIENT_KEY_INTERFACE intf;
    STRING_HANDLE key_file;
};
typedef struct ENC_KEY_TAG ENC_KEY;

static bool validate_input_param_buffer(const SIZED_BUFFER *sb, const char *name)
{
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

    return result;
}

static bool validate_input_ciphertext_buffer(const SIZED_BUFFER *sb, unsigned char *version)
{
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
    return __FAILURE__;
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
            if (ecall_Encrypt(
                enc,
                &result,
                STRING_c_str(enc_key->key_file),
                plaintext->buffer,
                (int)plaintext->size,
                identity->buffer,
                (int)identity->size,
                initialization_vector->buffer,
                (int)initialization_vector->size,
                ciphertext->buffer,
                ciphertext->size) != OE_OK || result != 0)
                {
                    LOG_ERROR("Encrypt ecall failed");
                    result = __FAILURE__;
                }
        }
    }

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
            ENC_KEY *enc_key = (ENC_KEY*)key_handle;
            if (ecall_Decrypt(
                enc,
                &result,
                STRING_c_str(enc_key->key_file),
                ciphertext->buffer,
                (int)ciphertext->size,
                identity->buffer,
                (int)identity->size,
                initialization_vector->buffer,
                (int)initialization_vector->size,
                plaintext->buffer,
                plaintext->size) != OE_OK || result != 0)
                {
                    LOG_ERROR("Decrypt ecall failed");
                    result = __FAILURE__;
                }
        }
    }

    return result;
}

static void enc_key_destroy(KEY_HANDLE key_handle)
{
    int result;

    ENC_KEY *enc_key = (ENC_KEY*)key_handle;

    if (enc_key == NULL)
    {
        LOG_ERROR("Invalid key handle parameter");
    }
    else if (enc_key->key_file == NULL)
    {
        LOG_ERROR("NULL key file value");
    }
    else if (ecall_DeleteEncryptionKey(
                enc,
                &result,
                STRING_c_str(enc_key->key_file)) != OE_OK || result != 0)
    {
        LOG_ERROR("DeleteEncryptionKey ecall failed");
    }
    else
    {
        STRING_delete(enc_key->key_file);
        free(enc_key);
    }
}

int verify_enclave_encryption_key(STRING_HANDLE key_file)
{
    int result;

    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        result = __FAILURE__;
    }
    else if (ecall_VerifyEncryptionKey(
        enc,
        &result,
        STRING_c_str(key_file)) != OE_OK)
    {
        LOG_ERROR("VerifyEncryptionKey ecall failed");
        result = __FAILURE__;
    }

    return result;
}

int generate_save_enclave_encryption_key(STRING_HANDLE key_file)
{
    int result;

    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        result = __FAILURE__;
    }
    else if (ecall_CreateEncryptionKey(
        enc,
        &result,
        STRING_c_str(key_file)) != OE_OK)
    {
        LOG_ERROR("CreateEncryptionKey ecall failed");
        result = __FAILURE__;
    }

    return result;
}

int delete_enclave_encryption_key(STRING_HANDLE key_file)
{
    int result;

    if (key_file == NULL)
    {
        LOG_ERROR("Invalid key file parameter");
        result = __FAILURE__;
    }
    else if (ecall_DeleteEncryptionKey(
        enc,
        &result,
        STRING_c_str(key_file)) != OE_OK)
    {
        LOG_ERROR("DeleteEncryptionKey ecall failed");
        result = __FAILURE__;
    }

    return result;
}

KEY_HANDLE create_enclave_encryption_key(STRING_HANDLE key_file)
{
    int result = 0;

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
        else if (ecall_CreateEncryptionKey(
            enc,
            &result,
            STRING_c_str(enc_key->key_file)) != OE_OK || result != 0)
        {
            LOG_ERROR("CreateEncryptionKey ecall failed");
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

    return (KEY_HANDLE)enc_key;
}
