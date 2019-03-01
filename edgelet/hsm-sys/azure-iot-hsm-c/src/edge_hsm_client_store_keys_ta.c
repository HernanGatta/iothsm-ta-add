#include "edge_hsm_client_store.h"

#include "edge_sas_enclave_key.h"
#include "hsm_enclave_key.h"

static void destroy_key(STORE_ENTRY_KEY *key)
{
    STRING_delete(key->id);
    BUFFER_delete(key->key);
    free(key);
}

void destroy_keys(SINGLYLINKEDLIST_HANDLE keys)
{
    LIST_ITEM_HANDLE list_item;
    while ((list_item = singlylinkedlist_get_head_item(keys)) != NULL)
    {
        STORE_ENTRY_KEY *key_entry = (STORE_ENTRY_KEY*)singlylinkedlist_item_get_value(list_item);
        destroy_key(key_entry);
        singlylinkedlist_remove(keys, list_item);
    }
}

int edge_hsm_client_store_remove_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    HSM_KEY_T key_type,
    const char* key_name
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    int result;

    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle parameter");
        result = __FAILURE__;
    }
    else if ((key_type != HSM_KEY_SAS) && (key_type != HSM_KEY_ENCRYPTION))
    {
        LOG_ERROR("Invalid key type parameter");
        result = __FAILURE__;
    }
    else if ((key_name == NULL) || (strlen(key_name) == 0))
    {
        LOG_ERROR("Invalid key name parameter");
        result = __FAILURE__;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = __FAILURE__;
    }
    else
    {
        STRING_HANDLE key_file_handle;

        if ((key_file_handle = STRING_new()) == NULL)
        {
            LOG_ERROR("HSM store could not create string to hold file path to key %s", key_name);
            result = __FAILURE__;
        }
        else
        {
            if (build_enc_key_file_path(key_name, key_file_handle) != 0)
            {
                LOG_ERROR("HSM store could not construct path to key");
                result = __FAILURE__;
            }
            else if (key_type == HSM_KEY_ENCRYPTION)
            {
                if (verify_enclave_encryption_key(key_file_handle) == 0 &&
                    delete_enclave_encryption_key(key_file_handle) != 0)
                {
                    LOG_ERROR("Could not delete encryption key file");
                    result = __FAILURE__;
                }
                else
                {
                    result = 0;
                }
            }
            else
            {
                if (verify_enclave_sas_key(key_file_handle) == 0 &&
                    delete_enclave_sas_key(key_file_handle) != 0)
                {
                    LOG_ERROR("Could not delete SAS key file");
                    result = __FAILURE__;
                }
                else
                {
                    result = 0;
                }
            }

            STRING_delete(key_file_handle);
        }
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

KEY_HANDLE edge_hsm_client_open_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    HSM_KEY_T key_type,
    const char* key_name
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    KEY_HANDLE result;

    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle parameter");
        result = NULL;
    }
    else if ((key_type != HSM_KEY_SAS) && (key_type != HSM_KEY_ENCRYPTION))
    {
        LOG_ERROR("Invalid key type parameter");
        result = NULL;
    }
    else if ((key_name == NULL) || (strlen(key_name) == 0))
    {
        LOG_ERROR("Invalid key name parameter");
        result = NULL;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = NULL;
    }
    else
    {
        STRING_HANDLE key_file_handle;
        if ((key_file_handle = STRING_new()) == NULL)
        {
            LOG_ERROR("HSM store could not create string to hold file path to key %s", key_name);
            result = NULL;
        }
        else 
        {
            if (build_enc_key_file_path(key_name, key_file_handle) != 0)
            {
                LOG_ERROR("HSM store could not construct path to key");
                result = NULL;
            }
            else if (key_type == HSM_KEY_ENCRYPTION)
            {
                if (verify_enclave_encryption_key(key_file_handle) != 0)
                {
                    LOG_ERROR("HSM store could not find encryption key %s", key_name);
                    result = NULL;
                }
                else
                {
                    result = create_enclave_encryption_key(key_file_handle);
                }
            }
            else
            {
                if (verify_enclave_sas_key(key_file_handle) != 0)
                {
                    LOG_ERROR("HSM store could not find SAS key %s", key_name);
                    result = NULL;
                }
                else
                {
                    result = create_enclave_sas_key(key_file_handle);
                }
            }

            STRING_delete(key_file_handle);
        }
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

int edge_hsm_client_close_key(HSM_CLIENT_STORE_HANDLE handle, KEY_HANDLE key_handle)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);
    int result;

    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle parameter");
        result = __FAILURE__;
    }
    else if (key_handle == NULL)
    {
        LOG_ERROR("Invalid key handle parameter");
        result = __FAILURE__;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = __FAILURE__;
    }
    else
    {
        key_destroy(key_handle);
        result = 0;
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

int edge_hsm_client_store_insert_encryption_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* key_name
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);

    int result;

    STRING_HANDLE key_file_handle;

    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle value");
        result = __FAILURE__;
    }
    else if ((key_name == NULL) || (strlen(key_name) == 0))
    {
        LOG_ERROR("Invalid handle alias value");
        result = __FAILURE__;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = __FAILURE__;
    }
    else if ((key_file_handle = STRING_new()) == NULL)
    {
        LOG_ERROR("HSM store could not create string to hold file path to key %s", key_name);
        result = __FAILURE__;
    }
    else
    {
        if (build_enc_key_file_path(key_name, key_file_handle) != 0)
        {
            LOG_ERROR("HSM store could not construct path to key");
            result = __FAILURE__;
        }
        else if (verify_enclave_encryption_key(key_file_handle) == 0)
        {
            LOG_DEBUG("HSM store already has encryption key set %s", key_name);
            result = 0;
        }
        else
        {
            result = generate_save_enclave_encryption_key(key_file_handle);
        }
        
        STRING_delete(key_file_handle);
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}

int edge_hsm_client_store_insert_sas_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* key_name,
    const unsigned char* key,
    size_t key_size
)
{
    LOG_DEBUG("ENTER: %s", __FUNCTION__);

    int result;

    STRING_HANDLE key_file_handle;

    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle parameter");
        result = __FAILURE__;
    }
    else if ((key_name == NULL) || (strlen(key_name) == 0))
    {
        LOG_ERROR("Invalid key name parameter");
        result = __FAILURE__;
    }
    else if ((key == NULL) || (key_size == 0))
    {
        LOG_ERROR("Invalid key parameters");
        result = __FAILURE__;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = __FAILURE__;
    }
    else if ((key_file_handle = STRING_new()) == NULL)
    {
        LOG_ERROR("HSM store could not create string to hold file path to key %s", key_name);
        result = __FAILURE__;
    }
    else
    {
        if (build_enc_key_file_path(key_name, key_file_handle) != 0)
        {
            LOG_ERROR("HSM store could not construct path to key");
            result = __FAILURE__;
        }
        else if (verify_enclave_sas_key(key_file_handle) == 0 &&
                 delete_enclave_sas_key(key_file_handle) != 0)
        {
            LOG_DEBUG("HSM store already has SAS key set %s but could not be removed", key_name);
            result = __FAILURE__;
        }
        else
        {
            result = import_enclave_sas_key(key_file_handle, key, key_size);
        }

        STRING_delete(key_file_handle);
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}
