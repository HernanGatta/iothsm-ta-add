#include "edge_hsm_client_store.h"
#include "hsm_key.h"
#include "hsm_enclave_key.h"

static STORE_ENTRY_KEY* create_key_entry
(
    const char *key_name,
    const unsigned char* key,
    size_t key_size
)
{
    STORE_ENTRY_KEY *result;

    if ((result = malloc(sizeof(STORE_ENTRY_KEY))) == NULL)
    {
        LOG_ERROR("Could not allocate memory to store the key %s", key_name);
    }
    else if ((result->id = STRING_construct(key_name)) == NULL)
    {
        LOG_ERROR("Could not allocate string handle for key %s", key_name);
        free(result);
        result = NULL;
    }
    else if ((result->key = BUFFER_create(key, key_size)) == NULL)
    {
        LOG_ERROR("Could not allocate buffer for key %s", key_name);
        STRING_delete(result->id);
        free(result);
        result = NULL;
    }

    return result;
}

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

static bool remove_key_entry_cb
(
    const void *item,
    const void *match_context,
    bool *continue_processing
)
{
    bool result;
    STORE_ENTRY_KEY* key = (STORE_ENTRY_KEY*)item;

    if (strcmp(STRING_c_str(key->id), (const char*)match_context) == 0)
    {
        destroy_key(key);
        *continue_processing = false;
        result = true;
    }
    else
    {
        *continue_processing = true;
        result = false;
    }

    return result;
}

static bool find_key_cb(LIST_ITEM_HANDLE list_item, const void *match_context)
{
    bool result;

    STORE_ENTRY_KEY *key = (STORE_ENTRY_KEY*)singlylinkedlist_item_get_value(list_item);
    if (strcmp(STRING_c_str(key->id), (const char*)match_context) == 0)
    {
        result = true;
    }
    else
    {
        result = false;
    }

    return result;
}

static STORE_ENTRY_KEY* get_key(const CRYPTO_STORE *store, HSM_KEY_T key_type, const char *key_name)
{
    STORE_ENTRY_KEY *result = NULL;
    SINGLYLINKEDLIST_HANDLE key_list = (key_type == HSM_KEY_SAS) ? store->store_entry->sas_keys :
                                                                   store->store_entry->sym_enc_keys;
    LIST_ITEM_HANDLE list_item = singlylinkedlist_find(key_list, find_key_cb, key_name);
    if (list_item != NULL)
    {
        result = (STORE_ENTRY_KEY*)singlylinkedlist_item_get_value(list_item);
    }

    return result;
}

static int remove_key
(
    CRYPTO_STORE *store,
    HSM_KEY_T key_type,
    const char *key_name
)
{
    int result;
    SINGLYLINKEDLIST_HANDLE key_list = (key_type == HSM_KEY_SAS) ? store->store_entry->sas_keys :
                                                                   store->store_entry->sym_enc_keys;
    LIST_ITEM_HANDLE list_item = singlylinkedlist_find(key_list, find_key_cb, key_name);
    if (list_item == NULL)
    {
        LOG_DEBUG("Key not found %s", key_name);
        result = __FAILURE__;
    }
    else
    {
        STORE_ENTRY_KEY *key_entry = (STORE_ENTRY_KEY*)singlylinkedlist_item_get_value(list_item);
        destroy_key(key_entry);
        singlylinkedlist_remove(key_list, list_item);
        result = 0;
    }

    return result;
}

static int put_key
(
    CRYPTO_STORE *store,
    HSM_KEY_T key_type,
    const char *key_name,
    const unsigned char* key,
    size_t key_size
)
{
    int result;
    STORE_ENTRY_KEY *key_entry;
    SINGLYLINKEDLIST_HANDLE key_list = (key_type == HSM_KEY_SAS) ? store->store_entry->sas_keys :
                                                                   store->store_entry->sym_enc_keys;
    (void)singlylinkedlist_remove_if(key_list, remove_key_entry_cb, key_name);
    if ((key_entry = create_key_entry(key_name, key, key_size)) == NULL)
    {
        LOG_ERROR("Could not allocate memory to store key %s", key_name);
        result = __FAILURE__;
    }
    else if (singlylinkedlist_add(key_list, key_entry) == NULL)
    {
        LOG_ERROR("Could not insert key in the key store");
        destroy_key(key_entry);
        result = __FAILURE__;
    }
    else
    {
        result = 0;
    }

    return result;
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
        result = 0;
        if (key_type == HSM_KEY_ENCRYPTION)
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
                else if (verify_enclave_encryption_key(key_file_handle) == 0 &&
                         delete_enclave_encryption_key(key_file_handle) != 0)
                {
                    LOG_ERROR("Could not delete key file");
                    result = __FAILURE__;
                }
                else
                {
                    result = 0;
                }
                
                STRING_delete(key_file_handle);
            }
        }
        else
        {
            if (remove_key((CRYPTO_STORE*)handle, key_type, key_name) != 0)
            {
                LOG_ERROR("Key not loaded in HSM store %s", key_name);
                result = __FAILURE__;
            }
            else
            {
                result = 0;
            }
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
        CRYPTO_STORE *store = (CRYPTO_STORE*)handle;

        if (key_type == HSM_KEY_ENCRYPTION)
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
                else if (verify_enclave_encryption_key(key_file_handle) != 0)
                {
                    LOG_ERROR("HSM store could not find encryption key %s", key_name);
                    result = NULL;
                }
                else
                {
                    result = create_enclave_encryption_key(key_file_handle);
                }

                STRING_delete(key_file_handle);
            }
        }
        else
        {
            STORE_ENTRY_KEY* key_entry;
            size_t buffer_size = 0;
            const unsigned char *buffer_ptr = NULL;
            if ((key_entry = get_key(store, key_type, key_name)) == NULL)
            {
                LOG_ERROR("Could not find key name %s", key_name);
                result = NULL;
            }
            else if (((buffer_ptr = BUFFER_u_char(key_entry->key)) == NULL) ||
                     (BUFFER_size(key_entry->key, &buffer_size) != 0) ||
                     (buffer_size == 0))
            {
                LOG_ERROR("Invalid key buffer for %s", key_name);
                result = NULL;
            }
            else
            {
                result = create_sas_key(buffer_ptr, buffer_size);
            }
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
    else
    {
        result = put_key((CRYPTO_STORE*)handle, HSM_KEY_SAS, key_name, key, key_size);
    }

    LOG_DEBUG("EXIT: %s (%i)", __FUNCTION__, result);
    return result;
}
