#include "edge_hsm_client_store.h"

HSM_STATE_T g_hsm_state = HSM_STATE_UNPROVISIONED;

CRYPTO_STORE* g_crypto_store = NULL;
int g_store_ref_count = 0;

//##############################################################################
// STORE_ENTRY_KEY helpers
//##############################################################################
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

static bool key_exists(const CRYPTO_STORE *store, HSM_KEY_T key_type, const char *key_name)
{
    STORE_ENTRY_KEY *entry = get_key(store, key_type, key_name);
    return (entry != NULL) ? true : false;
}

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

static void destroy_keys(SINGLYLINKEDLIST_HANDLE keys)
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

static int save_encryption_key_to_file(const char *key_name, unsigned char *key, size_t key_size)
{
    int result;
    STRING_HANDLE key_file_handle;

    if ((key_file_handle = STRING_new()) == NULL)
    {
        LOG_ERROR("Could not create string handle");
        result = __FAILURE__;
    }
    {
        const char *key_file;
        if (build_enc_key_file_path(key_name, key_file_handle) != 0)
        {
            LOG_ERROR("Could not construct path to key");
            result = __FAILURE__;
        }
        else if ((key_file = STRING_c_str(key_file_handle)) == NULL)
        {
            LOG_ERROR("Key file path NULL");
            result = __FAILURE__;
        }
        else if (write_buffer_to_file(key_file, key, key_size, true) != 0)
        {
            LOG_ERROR("Could not write key to file");
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
        STRING_delete(key_file_handle);
    }

    return result;
}

static int load_encryption_key_from_file(CRYPTO_STORE* store, const char *key_name)
{
    int result;
    STRING_HANDLE key_file_handle;

    if ((key_file_handle = STRING_new()) == NULL)
    {
        LOG_ERROR("Could not create string handle");
        result = __FAILURE__;
    }
    else
    {
        const char *key_file;
        unsigned char *key = NULL;
        size_t key_size = 0;

        if (build_enc_key_file_path(key_name, key_file_handle) != 0)
        {
            LOG_ERROR("Could not construct path to key");
            result = __FAILURE__;
        }
        else if ((key_file = STRING_c_str(key_file_handle)) == NULL)
        {
            LOG_ERROR("Key file path NULL");
            result = __FAILURE__;
        }
        else if (((key = read_file_into_buffer(key_file, &key_size)) == NULL) ||
                  (key_size == 0))
        {
            LOG_ERROR("Could not read key from file. Key size %zu", key_size);
            result = __FAILURE__;
        }
        else
        {
            result = put_key(store, HSM_KEY_ENCRYPTION, key_name, key, key_size);
        }

        if (key != NULL)
        {
            free(key);
        }
        STRING_delete(key_file_handle);
    }

    return result;
}

static int delete_encryption_key_file(const char *key_name)
{
    int result;
    STRING_HANDLE key_file_handle;

    if ((key_file_handle = STRING_new()) == NULL)
    {
        LOG_ERROR("Could not create string handle");
        result = __FAILURE__;
    }
    else
    {
        const char *key_file;
        if (build_enc_key_file_path(key_name, key_file_handle) != 0)
        {
            LOG_ERROR("Could not construct path to key");
            result = __FAILURE__;
        }
        else if ((key_file = STRING_c_str(key_file_handle)) == NULL)
        {
            LOG_ERROR("Key file path NULL");
            result = __FAILURE__;
        }
        else if (is_file_valid(key_file) && (delete_file(key_file) != 0))
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

    return result;
}

//##############################################################################
// CRYPTO_STORE helpers
//##############################################################################
static CRYPTO_STORE* create_store(const char *store_name)
{
    CRYPTO_STORE_ENTRY *store_entry;
    STRING_HANDLE store_id;
    CRYPTO_STORE *result;

    if ((result = (CRYPTO_STORE*)malloc(sizeof(CRYPTO_STORE))) == NULL)
    {
        LOG_ERROR("Could not allocate memory to create the store");
    }
    else if ((store_entry = (CRYPTO_STORE_ENTRY*)malloc(sizeof(CRYPTO_STORE_ENTRY))) == NULL)
    {
        LOG_ERROR("Could not allocate memory for store entry");
        free(result);
        result = NULL;
    }
    else if ((store_entry->sas_keys = singlylinkedlist_create()) == NULL)
    {
        LOG_ERROR("Could not allocate SAS keys list");
        free(store_entry);
        free(result);
        result = NULL;
    }
    else if ((store_entry->sym_enc_keys = singlylinkedlist_create()) == NULL)
    {
        LOG_ERROR("Could not allocate encryption keys list");
        singlylinkedlist_destroy(store_entry->sas_keys);
        free(store_entry);
        free(result);
        result = NULL;
    }
    else if ((store_entry->pki_certs = singlylinkedlist_create()) == NULL)
    {
        LOG_ERROR("Could not allocate certs list");
        singlylinkedlist_destroy(store_entry->sym_enc_keys);
        singlylinkedlist_destroy(store_entry->sas_keys);
        free(store_entry);
        free(result);
        result = NULL;
    }
    else if ((store_entry->pki_trusted_certs = singlylinkedlist_create()) == NULL)
    {
        LOG_ERROR("Could not allocate trusted certs list");
        singlylinkedlist_destroy(store_entry->pki_certs);
        singlylinkedlist_destroy(store_entry->sym_enc_keys);
        singlylinkedlist_destroy(store_entry->sas_keys);
        free(store_entry);
        free(result);
        result = NULL;
    }
    else if ((store_id = STRING_construct(store_name)) == NULL)
    {
        LOG_ERROR("Could not allocate store id");
        singlylinkedlist_destroy(store_entry->pki_trusted_certs);
        singlylinkedlist_destroy(store_entry->pki_certs);
        singlylinkedlist_destroy(store_entry->sym_enc_keys);
        singlylinkedlist_destroy(store_entry->sas_keys);
        free(store_entry);
        free(result);
        result = NULL;
    }
    else
    {
        result->ref_count = 1;
        result->store_entry = store_entry;
        result->id = store_id;
    }

    return result;
}

static void destroy_store(CRYPTO_STORE *store)
{
    STRING_delete(store->id);
    destroy_pki_trusted_certs(store->store_entry->pki_trusted_certs);
    singlylinkedlist_destroy(store->store_entry->pki_trusted_certs);
    destroy_pki_certs(store->store_entry->pki_certs);
    singlylinkedlist_destroy(store->store_entry->pki_certs);
    destroy_keys(store->store_entry->sym_enc_keys);
    singlylinkedlist_destroy(store->store_entry->sym_enc_keys);
    destroy_keys(store->store_entry->sas_keys);
    singlylinkedlist_destroy(store->store_entry->sas_keys);
    free(store->store_entry);
    free(store);
}

static int hsm_provision(void)
{
    int result;

    if (get_base_dir() == NULL)
    {
        LOG_ERROR("HSM base directory does not exist. "
                  "Set environment variable IOTEDGE_HOMEDIR to a valid path.");
        result = __FAILURE__;
    }
    else
    {
        result = hsm_provision_edge_certificates();
    }

    return result;
}

static int hsm_deprovision(void)
{
    return 0;
}

//##############################################################################
// Store interface implementation
//##############################################################################
static int edge_hsm_client_store_create(const char* store_name)
{
    int result;

    if ((store_name == NULL) || (strlen(store_name) == 0))
    {
        result = __FAILURE__;
    }
    else if ((g_hsm_state == HSM_STATE_UNPROVISIONED) ||
             (g_hsm_state == HSM_STATE_PROVISIONING_ERROR))
    {
        g_crypto_store = create_store(store_name);
        if (g_crypto_store == NULL)
        {
            LOG_ERROR("Could not create HSM store");
            result = __FAILURE__;
        }
        else
        {
            if (hsm_provision() != 0)
            {
                destroy_store(g_crypto_store);
                g_crypto_store = NULL;
                g_hsm_state = HSM_STATE_PROVISIONING_ERROR;
                result = __FAILURE__;
            }
            else
            {
                g_store_ref_count = 1;
                g_hsm_state = HSM_STATE_PROVISIONED;
                result = 0;
            }
        }
    }
    else
    {
        g_store_ref_count++;
        result = 0;
    }

    return result;
}

static int edge_hsm_client_store_destroy(const char* store_name)
{
    int result;

    if ((store_name == NULL) || (strlen(store_name) == 0))
    {
        LOG_ERROR("Invald store name parameter");
        result = __FAILURE__;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = __FAILURE__;
    }
    else
    {
        g_store_ref_count--;
        if (g_store_ref_count == 0)
        {
            result = hsm_deprovision();
            destroy_store(g_crypto_store);
            g_hsm_state = HSM_STATE_UNPROVISIONED;
            g_crypto_store = NULL;
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

static HSM_CLIENT_STORE_HANDLE edge_hsm_client_store_open(const char* store_name)
{
    HSM_CLIENT_STORE_HANDLE result;

    if ((store_name == NULL) || (strlen(store_name) == 0))
    {
        LOG_ERROR("Invald store name parameter");
        result = NULL;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = NULL;
    }
    else
    {
        result = (HSM_CLIENT_STORE_HANDLE)g_crypto_store;
    }

    return result;
}

static int edge_hsm_client_store_close(HSM_CLIENT_STORE_HANDLE handle)
{
    int result;

    if (handle == NULL)
    {
        LOG_ERROR("Invald store name parameter");
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
    }

    return result;
}

static int edge_hsm_client_store_insert_sas_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* key_name,
    const unsigned char* key,
    size_t key_size
)
{
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

    return result;
}

static int edge_hsm_client_store_remove_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    HSM_KEY_T key_type,
    const char* key_name
)
{
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
            if (remove_key((CRYPTO_STORE*)handle, key_type, key_name) != 0)
            {
                LOG_DEBUG("Encryption key not loaded in HSM store %s", key_name);
            }
            result = delete_encryption_key_file(key_name);
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

    return result;
}

static KEY_HANDLE edge_hsm_client_open_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    HSM_KEY_T key_type,
    const char* key_name
)
{
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
        bool do_key_create = true;
        CRYPTO_STORE *store = (CRYPTO_STORE*)handle;

        if (key_type == HSM_KEY_ENCRYPTION)
        {
            if (!key_exists(store, HSM_KEY_ENCRYPTION, key_name) &&
                (load_encryption_key_from_file(store, key_name) != 0))
            {
                LOG_ERROR("HSM store could not load encryption key %s", key_name);
                do_key_create = false;
            }
        }

        if (!do_key_create)
        {
            result = NULL;
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
                if (key_type == HSM_KEY_ENCRYPTION)
                {
                    result = create_encryption_key(buffer_ptr, buffer_size);
                }
                else
                {
                    result = create_sas_key(buffer_ptr, buffer_size);
                }
            }
        }
    }

    return result;
}

static int edge_hsm_client_close_key(HSM_CLIENT_STORE_HANDLE handle, KEY_HANDLE key_handle)
{
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

    return result;
}

static int edge_hsm_client_store_insert_encryption_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* key_name
)
{
    int result;

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
    else if (key_exists((CRYPTO_STORE*)handle, HSM_KEY_ENCRYPTION, key_name))
    {
        LOG_DEBUG("HSM store already has encryption key set %s", key_name);
        result = 0;
    }
    else
    {
        size_t key_size = 0;
        unsigned char *key = NULL;
        if (generate_encryption_key(&key, &key_size) != 0)
        {
            LOG_ERROR("Could not create encryption key for %s", key_name);
            result = __FAILURE__;
        }
        else
        {
            if (save_encryption_key_to_file(key_name, key, key_size) != 0)
            {
                LOG_ERROR("Could not persist encryption key %s to file", key_name);
                result = __FAILURE__;
            }
            else
            {
                result = 0;
            }
            free(key);
        }
    }

    return result;
}

static const HSM_CLIENT_STORE_INTERFACE edge_hsm_client_store_interface =
{
    edge_hsm_client_store_create,
    edge_hsm_client_store_destroy,
    edge_hsm_client_store_open,
    edge_hsm_client_store_close,
    edge_hsm_client_open_key,
    edge_hsm_client_close_key,
    edge_hsm_client_store_remove_key,
    edge_hsm_client_store_insert_sas_key,
    edge_hsm_client_store_insert_encryption_key,
    edge_hsm_client_store_create_pki_cert,
    edge_hsm_client_store_get_pki_cert,
    edge_hsm_client_store_remove_pki_cert,
    edge_hsm_client_store_insert_pki_trusted_cert,
    edge_hsm_client_store_get_pki_trusted_certs,
    edge_hsm_client_store_remove_pki_trusted_cert
};

const HSM_CLIENT_STORE_INTERFACE* hsm_client_store_interface(void)
{
    return &edge_hsm_client_store_interface;
}
