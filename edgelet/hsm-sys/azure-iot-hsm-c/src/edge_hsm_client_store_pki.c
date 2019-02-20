#include "edge_hsm_client_store.h"

static int edge_hsm_client_store_create_pki_cert_internal
(
    HSM_CLIENT_STORE_HANDLE handle,
    CERT_PROPS_HANDLE cert_props_handle,
    int ca_path_len
);

//##############################################################################
// STORE_ENTRY_PKI_CERT helpers
//##############################################################################
static bool find_pki_cert_cb(LIST_ITEM_HANDLE list_item, const void *match_context)
{
    bool result;
    STORE_ENTRY_PKI_CERT *cert = (STORE_ENTRY_PKI_CERT*)singlylinkedlist_item_get_value(list_item);
    if (strcmp(STRING_c_str(cert->id), (const char*)match_context) == 0)
    {
        result = true;
    }
    else
    {
        result = false;
    }

    return result;
}

static STORE_ENTRY_PKI_CERT* get_pki_cert
(
    const CRYPTO_STORE *store,
    const char *cert_alias
)
{
    STORE_ENTRY_PKI_CERT *result = NULL;
    SINGLYLINKEDLIST_HANDLE certs_list = store->store_entry->pki_certs;
    LIST_ITEM_HANDLE list_item = singlylinkedlist_find(certs_list,
                                                       find_pki_cert_cb,
                                                       cert_alias);
    if (list_item != NULL)
    {
        result = (STORE_ENTRY_PKI_CERT*)singlylinkedlist_item_get_value(list_item);
    }
    return result;
}

static CERT_INFO_HANDLE prepare_cert_info_handle
(
    const CRYPTO_STORE *store,
    STORE_ENTRY_PKI_CERT *cert_entry
)
{
    (void)store;
    CERT_INFO_HANDLE result;
    char *cert_contents = NULL, *private_key_contents = NULL;
    size_t private_key_size = 0;
    const char *cert_file;
    const char *pk_file;

    if ((pk_file = STRING_c_str(cert_entry->private_key_file)) == NULL)
    {
        LOG_ERROR("Private key file path is NULL");
        result = NULL;
    }
    else if ((private_key_contents = read_file_into_cstring(pk_file, &private_key_size)) == NULL)
    {
        LOG_ERROR("Could not load private key into buffer %s", pk_file);
        result = NULL;
    }
    else if ((cert_file = STRING_c_str(cert_entry->cert_file)) == NULL)
    {
        LOG_ERROR("Certificate file path NULL");
        result = NULL;
    }
    else if ((cert_contents = read_file_into_cstring(cert_file, NULL)) == NULL)
    {
        LOG_ERROR("Could not read certificate into buffer %s", cert_file);
        result = NULL;
    }
    else
    {
        result = certificate_info_create(cert_contents,
                                         private_key_contents,
                                         private_key_size,
                                         (private_key_size != 0) ? PRIVATE_KEY_PAYLOAD :
                                                                   PRIVATE_KEY_UNKNOWN);
    }

    if (cert_contents != NULL)
    {
        free(cert_contents);
    }
    if (private_key_contents != NULL)
    {
        free(private_key_contents);
    }

    return result;
}

static STORE_ENTRY_PKI_CERT* create_pki_cert_entry
(
    const char *alias,
    const char *issuer_alias,
    const char *certificate_file,
    const char *private_key_file
)
{
    STORE_ENTRY_PKI_CERT *result;

    if ((result = malloc(sizeof(STORE_ENTRY_PKI_CERT))) == NULL)
    {
        LOG_ERROR("Could not allocate memory to store the certificate for alias %s", alias);
    }
    else if ((result->id = STRING_construct(alias)) == NULL)
    {
        LOG_ERROR("Could not allocate string handle for alias %s", alias);
        free(result);
        result = NULL;
    }
    else if ((result->issuer_id = STRING_construct(issuer_alias)) == NULL)
    {
        LOG_ERROR("Could not allocate string handle for issuer for alias %s", alias);
        STRING_delete(result->id);
        free(result);
        result = NULL;
    }
    else if ((result->cert_file = STRING_construct(certificate_file)) == NULL)
    {
        LOG_ERROR("Could not allocate string handle for cert file for alias %s", alias);
        STRING_delete(result->issuer_id);
        STRING_delete(result->id);
        free(result);
        result = NULL;
    }
    else if ((result->private_key_file = STRING_construct(private_key_file)) == NULL)
    {
        LOG_ERROR("Could not allocate string handle for private key file for alias %s", alias);
        STRING_delete(result->cert_file);
        STRING_delete(result->issuer_id);
        STRING_delete(result->id);
        free(result);
        result = NULL;
    }

    return result;
}

static void destroy_pki_cert(STORE_ENTRY_PKI_CERT *pki_cert)
{
    STRING_delete(pki_cert->id);
    STRING_delete(pki_cert->issuer_id);
    STRING_delete(pki_cert->cert_file);
    STRING_delete(pki_cert->private_key_file);
    free(pki_cert);
}

static bool remove_cert_entry_cb
(
    const void *item,
    const void *match_context,
    bool *continue_processing
)
{
    bool result;
    STORE_ENTRY_PKI_CERT *pki_cert = (STORE_ENTRY_PKI_CERT*)item;
    if (strcmp(STRING_c_str(pki_cert->id), (const char*)match_context) == 0)
    {
        destroy_pki_cert(pki_cert);
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

static int put_pki_cert
(
    CRYPTO_STORE *store,
    const char *alias,
    const char *issuer_alias,
    const char *certificate_file,
    const char *private_key_file
)
{
    int result;
    STORE_ENTRY_PKI_CERT *cert_entry;

    cert_entry = create_pki_cert_entry(alias, issuer_alias, certificate_file, private_key_file);
    if (cert_entry == NULL)
    {
        LOG_ERROR("Could not allocate memory to store certificate and or key for %s", alias);
        result = __FAILURE__;
    }
    else
    {
        SINGLYLINKEDLIST_HANDLE cert_list = store->store_entry->pki_certs;
        (void)singlylinkedlist_remove_if(cert_list, remove_cert_entry_cb, alias);
        if (singlylinkedlist_add(cert_list, cert_entry) == NULL)
        {
            LOG_ERROR("Could not insert cert and key in the store");
            destroy_pki_cert(cert_entry);
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

static int remove_pki_cert(CRYPTO_STORE *store, const char *alias)
{
    int result;
    SINGLYLINKEDLIST_HANDLE certs_list = store->store_entry->pki_certs;
    LIST_ITEM_HANDLE list_item = singlylinkedlist_find(certs_list, find_pki_cert_cb, alias);
    if (list_item == NULL)
    {
        LOG_DEBUG("Certificate not found %s", alias);
        result = __FAILURE__;
    }
    else
    {
        STORE_ENTRY_PKI_CERT *pki_cert;
        pki_cert = (STORE_ENTRY_PKI_CERT*)singlylinkedlist_item_get_value(list_item);
        destroy_pki_cert(pki_cert);
        singlylinkedlist_remove(certs_list, list_item);
        result = 0;
    }

    return result;
}

void destroy_pki_certs(SINGLYLINKEDLIST_HANDLE certs)
{
    LIST_ITEM_HANDLE list_item;
    while ((list_item = singlylinkedlist_get_head_item(certs)) != NULL)
    {
        STORE_ENTRY_PKI_CERT *pki_cert;
        pki_cert = (STORE_ENTRY_PKI_CERT*)singlylinkedlist_item_get_value(list_item);
        destroy_pki_cert(pki_cert);
        singlylinkedlist_remove(certs, list_item);
    }
}

//##############################################################################
// STORE_ENTRY_PKI_TRUSTED_CERT helpers
//##############################################################################

static bool find_pki_trusted_cert_cb(LIST_ITEM_HANDLE list_item, const void *match_context)
{
    bool result;
    STORE_ENTRY_PKI_CERT *cert = (STORE_ENTRY_PKI_CERT*)singlylinkedlist_item_get_value(list_item);
    if (strcmp(STRING_c_str(cert->id), (const char*)match_context) == 0)
    {
        result = true;
    }
    else
    {
        result = false;
    }

    return result;
}

static STORE_ENTRY_PKI_TRUSTED_CERT* create_pki_trusted_cert_entry
(
    const char *name,
    const char *certificate_file
)
{
    STORE_ENTRY_PKI_TRUSTED_CERT *result;

    if ((result = malloc(sizeof(STORE_ENTRY_PKI_TRUSTED_CERT))) == NULL)
    {
        LOG_ERROR("Could not allocate memory to store the certificate for %s", name);
    }
    else if ((result->id = STRING_construct(name)) == NULL)
    {
        LOG_ERROR("Could not allocate string handle for %s", name);
        free(result);
        result = NULL;
    }
    else if ((result->cert_file = STRING_construct(certificate_file)) == NULL)
    {
        LOG_ERROR("Could not allocate string handle for the file path for %s", name);
        STRING_delete(result->id);
        free(result);
        result = NULL;
    }

    return result;
}

static void destroy_trusted_cert(STORE_ENTRY_PKI_TRUSTED_CERT *trusted_cert)
{
    STRING_delete(trusted_cert->id);
    STRING_delete(trusted_cert->cert_file);
    free(trusted_cert);
}

static bool remove_trusted_cert_entry_cb
(
    const void* item,
    const void* match_context,
    bool* continue_processing
)
{
    bool result;
    STORE_ENTRY_PKI_TRUSTED_CERT* trusted_cert = (STORE_ENTRY_PKI_TRUSTED_CERT*)item;
    if (strcmp(STRING_c_str(trusted_cert->id), (const char*)match_context) == 0)
    {
        destroy_trusted_cert(trusted_cert);
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

static CERT_INFO_HANDLE prepare_trusted_certs_info(CRYPTO_STORE *store)
{
    CERT_INFO_HANDLE result;
    LIST_ITEM_HANDLE list_item;
    SINGLYLINKEDLIST_HANDLE cert_list = store->store_entry->pki_trusted_certs;
    int list_count = 0;

    list_item = singlylinkedlist_get_head_item(cert_list);
    while (list_item != NULL)
    {
        list_count++;
        list_item = singlylinkedlist_get_next_item(list_item);
    }

    if (list_count > 0)
    {
        char **trusted_files;
        int index = 0;
        if ((trusted_files = (char **)calloc(list_count, sizeof(const char*))) == NULL)
        {
            LOG_ERROR("Could not allocate memory to store list of trusted cert files");
            result = NULL;
        }
        else
        {
            char *all_certs;
            list_item = singlylinkedlist_get_head_item(cert_list);
            while (list_item != NULL)
            {
                STORE_ENTRY_PKI_TRUSTED_CERT *trusted_cert;
                trusted_cert = (STORE_ENTRY_PKI_TRUSTED_CERT*)singlylinkedlist_item_get_value(list_item);
                trusted_files[index] = (char*)STRING_c_str(trusted_cert->cert_file);
                index++;
                list_item = singlylinkedlist_get_next_item(list_item);
            }
            if ((all_certs = concat_files_to_cstring((const char**)trusted_files, list_count)) == NULL)
            {
                LOG_ERROR("Could not concat all the trusted cert files");
                result = NULL;
            }
            else
            {
                result = certificate_info_create(all_certs, NULL, 0, PRIVATE_KEY_UNKNOWN);
                free(all_certs);
            }
            free(trusted_files);
        }
    }
    else
    {
        result = NULL;
    }

    return result;
}

void destroy_pki_trusted_certs(SINGLYLINKEDLIST_HANDLE trusted_certs)
{
    LIST_ITEM_HANDLE list_item;
    while ((list_item = singlylinkedlist_get_head_item(trusted_certs)) != NULL)
    {
        STORE_ENTRY_PKI_TRUSTED_CERT *trusted_cert;
        trusted_cert = (STORE_ENTRY_PKI_TRUSTED_CERT*)singlylinkedlist_item_get_value(list_item);
        destroy_trusted_cert(trusted_cert);
        singlylinkedlist_remove(trusted_certs, list_item);
    }
}

static int put_pki_trusted_cert
(
    CRYPTO_STORE *store,
    const char *alias,
    const char *certificate_file
)
{
    int result;
    STORE_ENTRY_PKI_TRUSTED_CERT *trusted_cert_entry;
    SINGLYLINKEDLIST_HANDLE cert_list = store->store_entry->pki_trusted_certs;
    (void)singlylinkedlist_remove_if(cert_list, remove_trusted_cert_entry_cb, alias);
    trusted_cert_entry = create_pki_trusted_cert_entry(alias, certificate_file);
    if (trusted_cert_entry == NULL)
    {
        LOG_ERROR("Could not allocate memory to store trusted certificate for %s", alias);
        result = __FAILURE__;
    }
    else
    {
        if (singlylinkedlist_add(cert_list, trusted_cert_entry) == NULL)
        {
            LOG_ERROR("Could not insert cert and key in the store");
            destroy_trusted_cert(trusted_cert_entry);
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

static int remove_pki_trusted_cert(CRYPTO_STORE *store, const char *alias)
{
    int result;
    SINGLYLINKEDLIST_HANDLE certs_list = store->store_entry->pki_trusted_certs;
    LIST_ITEM_HANDLE list_item = singlylinkedlist_find(certs_list, find_pki_trusted_cert_cb, alias);
    if (list_item == NULL)
    {
        LOG_ERROR("Trusted certificate not found %s", alias);
        result = __FAILURE__;
    }
    else
    {
        STORE_ENTRY_PKI_TRUSTED_CERT *pki_cert;
        pki_cert = (STORE_ENTRY_PKI_TRUSTED_CERT*)singlylinkedlist_item_get_value(list_item);
        destroy_trusted_cert(pki_cert);
        singlylinkedlist_remove(certs_list, list_item);
        result = 0;
    }

    return result;
}

//##############################################################################
// HSM certificate provisioning
//##############################################################################
static CERT_PROPS_HANDLE create_ca_certificate_properties
(
    const char *common_name,
    uint64_t validity,
    const char *alias,
    const char *issuer_alias,
    CERTIFICATE_TYPE type
)
{
    CERT_PROPS_HANDLE certificate_props = cert_properties_create();

    if (certificate_props == NULL)
    {
        LOG_ERROR("Could not create certificate props for %s", alias);
    }
    else if (set_common_name(certificate_props, common_name) != 0)
    {
        LOG_ERROR("Could not set common name for %s", alias);
        cert_properties_destroy(certificate_props);
        certificate_props = NULL;
    }
    else if (set_validity_seconds(certificate_props, validity) != 0)
    {
        LOG_ERROR("Could not set validity for %s", alias);
        cert_properties_destroy(certificate_props);
        certificate_props = NULL;
    }
    else if (set_alias(certificate_props, alias) != 0)
    {
        LOG_ERROR("Could not set alias for %s", alias);
        cert_properties_destroy(certificate_props);
        certificate_props = NULL;
    }
    else if (set_issuer_alias(certificate_props, issuer_alias) != 0)
    {
        LOG_ERROR("Could not set issuer alias for %s", alias);
        cert_properties_destroy(certificate_props);
        certificate_props = NULL;
    }
    else if (set_certificate_type(certificate_props, type) != 0)
    {
        LOG_ERROR("Could not set certificate type for %s", alias);
        cert_properties_destroy(certificate_props);
        certificate_props = NULL;
    }

    return certificate_props;
}

static int remove_if_cert_and_key_exist_by_alias
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char *alias
)
{
    int result;
    STRING_HANDLE alias_cert_handle = NULL;
    STRING_HANDLE alias_pk_handle = NULL;
    CRYPTO_STORE *store = (CRYPTO_STORE*)handle;

    if (((alias_cert_handle = STRING_new()) == NULL) ||
        ((alias_pk_handle = STRING_new()) == NULL))
    {
        LOG_ERROR("Could not allocate string handles for storing certificate and key paths");
        result = __FAILURE__;
    }
    else if (build_cert_file_paths(alias, alias_cert_handle, alias_pk_handle) != 0)
    {
        LOG_ERROR("Could not create file paths to the certificate and private key for alias %s", alias);
        result = __FAILURE__;
    }
    else
    {
        const char *cert_file_path = STRING_c_str(alias_cert_handle);
        const char *key_file_path = STRING_c_str(alias_pk_handle);

        if (!is_file_valid(cert_file_path) || !is_file_valid(key_file_path))
        {
            LOG_ERROR("Certificate and key file for alias do not exist %s", alias);
            result = __FAILURE__;
        }
        else
        {
            if (delete_file(cert_file_path) != 0)
            {
                LOG_ERROR("Could not delete certificate file for alias %s", alias);
                result = __FAILURE__;
            }
            else if (delete_file(key_file_path) != 0)
            {
                LOG_ERROR("Could not delete key file for alias %s", alias);
                result = __FAILURE__;
            }
            else if (remove_pki_cert(store, alias) != 0)
            {
                LOG_DEBUG("Could not remove certificate and key from store for alias %s", alias);
                result = __FAILURE__;
            }
            else
            {
                result = 0;
            }
        }
    }

    if (alias_cert_handle != NULL)
    {
        STRING_delete(alias_cert_handle);
    }
    if (alias_pk_handle != NULL)
    {
        STRING_delete(alias_pk_handle);
    }

    return result;
}

static int load_if_cert_and_key_exist_by_alias
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char *alias,
    const char *issuer_alias
)
{
    int result;

    STRING_HANDLE alias_cert_handle = NULL;
    STRING_HANDLE alias_pk_handle = NULL;

    if (((alias_cert_handle = STRING_new()) == NULL) ||
        ((alias_pk_handle = STRING_new()) == NULL))
    {
        LOG_ERROR("Could not allocate string handles for storing certificate and key paths");
        result = LOAD_ERR_FAILED;
    }
    else if (build_cert_file_paths(alias, alias_cert_handle, alias_pk_handle) != 0)
    {
        LOG_ERROR("Could not create file paths to the certificate and private key for alias %s", alias);
        result = LOAD_ERR_FAILED;
    }
    else
    {
        const char *cert_file_path = STRING_c_str(alias_cert_handle);
        const char *key_file_path = STRING_c_str(alias_pk_handle);
        bool verify_status = false;
        if (is_file_valid(cert_file_path) && is_file_valid(key_file_path))
        {
            if (verify_certificate_helper(handle, alias, issuer_alias,
                                          cert_file_path, key_file_path,
                                          &verify_status) != 0)
            {
                LOG_ERROR("Failure when verifying certificate for alias %s", alias);
                result = LOAD_ERR_FAILED;
            }
            else if (!verify_status)
            {
                LOG_ERROR("Certificate for alias is invalid %s", alias);
                result = LOAD_ERR_VERIFICATION_FAILED;
            }
            else
            {
                if (edge_hsm_client_store_insert_pki_cert(handle,
                                                          alias,
                                                          issuer_alias,
                                                          cert_file_path,
                                                          key_file_path) != 0)
                {
                    LOG_ERROR("Could not load certificates into store for alias %s", alias);
                    result = LOAD_ERR_FAILED;
                }
                else
                {
                    LOG_DEBUG("Successfully loaded pre-existing certificates for alias %s", alias);
                    result = LOAD_SUCCESS;
                }
            }
        }
        else
        {
            result = LOAD_ERR_NOT_FOUND;
        }
    }
    if (alias_cert_handle != NULL)
    {
        STRING_delete(alias_cert_handle);
    }
    if (alias_pk_handle != NULL)
    {
        STRING_delete(alias_pk_handle);
    }

    return result;
}

static int create_owner_ca_cert(void)
{
    int result;
    CERT_PROPS_HANDLE ca_props;
    ca_props = create_ca_certificate_properties(OWNER_CA_COMMON_NAME,
                                                CA_VALIDITY,
                                                OWNER_CA_ALIAS,
                                                OWNER_CA_ALIAS,
                                                CERTIFICATE_TYPE_CA);
    if (ca_props == NULL)
    {
        LOG_ERROR("Could not create certificate props for owner CA");
        result = __FAILURE__;
    }
    else
    {
        result = edge_hsm_client_store_create_pki_cert_internal(g_crypto_store, ca_props,
                                                                OWNER_CA_PATHLEN);
        cert_properties_destroy(ca_props);
    }

    return result;
}

static int create_device_ca_cert(void)
{
    int result;
    CERT_PROPS_HANDLE ca_props;
    ca_props = create_ca_certificate_properties(DEVICE_CA_COMMON_NAME,
                                                CA_VALIDITY,
                                                hsm_get_device_ca_alias(),
                                                OWNER_CA_ALIAS,
                                                CERTIFICATE_TYPE_CA);
    if (ca_props == NULL)
    {
        LOG_ERROR("Could not create certificate props for device CA");
        result = __FAILURE__;
    }
    else
    {
        result = edge_hsm_client_store_create_pki_cert_internal(g_crypto_store,
                                                                ca_props,
                                                                DEVICE_CA_PATHLEN);
        cert_properties_destroy(ca_props);
    }

    return result;
}

/**
 * Generate the Owner CA and Device CA certificate in order to enable the quick start scenario.
 * Validate each certificate since it might have expired or the issuer certificate has been
 * modified.
 */
static int generate_edge_hsm_certificates_if_needed(void)
{
    int result;

    int load_status = load_if_cert_and_key_exist_by_alias(g_crypto_store,
                                                          OWNER_CA_ALIAS,
                                                          OWNER_CA_ALIAS);

    if (load_status == LOAD_ERR_FAILED)
    {
        LOG_ERROR("Could not check and load owner CA certificate and key");
        result = __FAILURE__;
    }
    else if ((load_status == LOAD_ERR_VERIFICATION_FAILED) ||
             (load_status == LOAD_ERR_NOT_FOUND))
    {
        LOG_INFO("Load status %d. Regenerating owner and device CA certs and keys", load_status);
        if (create_owner_ca_cert() != 0)
        {
            result = __FAILURE__;
        }
        else if (create_device_ca_cert() != 0)
        {
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
    }
    else
    {
        // owner ca was successfully created, now load/create the device CA cert
        load_status = load_if_cert_and_key_exist_by_alias(g_crypto_store,
                                                          hsm_get_device_ca_alias(),
                                                          OWNER_CA_ALIAS);
        if (load_status == LOAD_ERR_FAILED)
        {
            LOG_ERROR("Could not check and load device CA certificate and key");
            result = __FAILURE__;
        }
        else if ((load_status == LOAD_ERR_VERIFICATION_FAILED) ||
                 (load_status == LOAD_ERR_NOT_FOUND))
        {
            LOG_DEBUG("Load status %d. Generating device CA cert and key", load_status);
            if (create_device_ca_cert() != 0)
            {
                result = __FAILURE__;
            }
            else
            {
                result = 0;
            }
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

static int get_tg_env_vars(char **trusted_certs_path, char **device_ca_path, char **device_pk_path)
{
    int result;

    if (hsm_get_env(ENV_TRUSTED_CA_CERTS_PATH, trusted_certs_path) != 0)
    {
        LOG_ERROR("Failed to read env variable %s", ENV_TRUSTED_CA_CERTS_PATH);
        result = __FAILURE__;
    }
    else if (hsm_get_env(ENV_DEVICE_CA_PATH, device_ca_path) != 0)
    {
        LOG_ERROR("Failed to read env variable %s", ENV_DEVICE_CA_PATH);
        result = __FAILURE__;
    }
    else if (hsm_get_env(ENV_DEVICE_PK_PATH, device_pk_path) != 0)
    {
        LOG_ERROR("Failed to read env variable %s", ENV_DEVICE_PK_PATH);
        result = __FAILURE__;
    }
    else
    {
        result = 0;
    }

    return result;
}

int hsm_provision_edge_certificates(void)
{
    int result;
    unsigned int mask = 0, i = 0;
    bool env_set = false;
    char *trusted_certs_path = NULL;
    char *device_ca_path = NULL;
    char *device_pk_path = NULL;

    if (get_tg_env_vars(&trusted_certs_path, &device_ca_path, &device_pk_path) != 0)
    {
        result = __FAILURE__;
    }
    else
    {
        if (trusted_certs_path != NULL)
        {
            if ((strlen(trusted_certs_path) != 0) && is_file_valid(trusted_certs_path))
            {
                mask |= 1 << i; i++;
            }
            else
            {
                LOG_ERROR("Path set in env variable %s is invalid or cannot be accessed: '%s'",
                          ENV_TRUSTED_CA_CERTS_PATH, trusted_certs_path);
            }
            env_set = true;
            LOG_DEBUG("Env %s set to %s", ENV_TRUSTED_CA_CERTS_PATH, trusted_certs_path);
        }
        else
        {
            LOG_DEBUG("Env %s is NULL", ENV_TRUSTED_CA_CERTS_PATH);
        }

        if (device_ca_path != NULL)
        {
            if ((strlen(device_ca_path) != 0) && is_file_valid(device_ca_path))
            {
                mask |= 1 << i; i++;
            }
            else
            {
                LOG_ERROR("Path set in env variable %s is invalid or cannot be accessed: '%s'",
                          ENV_DEVICE_CA_PATH, device_ca_path);

            }
            env_set = true;
            LOG_DEBUG("Env %s set to %s", ENV_DEVICE_CA_PATH, device_ca_path);
        }
        else
        {
            LOG_DEBUG("Env %s is NULL", ENV_DEVICE_CA_PATH);
        }

        if (device_pk_path != NULL)
        {
            if ((strlen(device_pk_path) != 0) && is_file_valid(device_pk_path))
            {
                mask |= 1 << i; i++;
            }
            else
            {
                LOG_ERROR("Path set in env variable %s is invalid or cannot be accessed: '%s'",
                        ENV_DEVICE_PK_PATH, device_pk_path);

            }
            env_set = true;
            LOG_DEBUG("Env %s set to %s", ENV_DEVICE_PK_PATH, device_pk_path);
        }
        else
        {
            LOG_DEBUG("Env %s is NULL", ENV_DEVICE_PK_PATH);
        }

        LOG_DEBUG("Transparent gateway setup mask 0x%02x", mask);

        if (env_set && (mask != 0x7))
        {
            LOG_ERROR("To operate Edge as a transparent gateway, set "
                      "env variables with valid values:\n  %s\n  %s\n  %s",
                      ENV_TRUSTED_CA_CERTS_PATH, ENV_DEVICE_CA_PATH, ENV_DEVICE_PK_PATH);
            result = __FAILURE__;
        }
        // none of the certificate files were provided so generate them if needed
        else if (!env_set && (generate_edge_hsm_certificates_if_needed() != 0))
        {
            LOG_ERROR("Failure generating required HSM certificates");
            result = __FAILURE__;
        }
        else if (env_set && (edge_hsm_client_store_insert_pki_cert(g_crypto_store,
                                                                hsm_get_device_ca_alias(),
                                                                hsm_get_device_ca_alias(), // since we don't know the issuer, we treat this certificate as the issuer
                                                                device_ca_path,
                                                                device_pk_path) != 0))
        {
            LOG_ERROR("Failure inserting device CA certificate and key into the HSM store`");
            result = __FAILURE__;
        }
        else
        {
            const char *trusted_ca;
            // all required certificate files are available/generated now setup the trust bundle
            if (trusted_certs_path == NULL)
            {
                // certificates were generated so set the Owner CA as the trusted CA cert
                STORE_ENTRY_PKI_CERT *store_entry;
                trusted_ca = NULL;
                if ((store_entry = get_pki_cert(g_crypto_store, OWNER_CA_ALIAS)) == NULL)
                {
                    LOG_ERROR("Failure obtaining owner CA certificate entry");
                }
                else if ((trusted_ca = STRING_c_str(store_entry->cert_file)) == NULL)
                {
                    LOG_ERROR("Failure obtaining owner CA certificate path");
                }
            }
            else
            {
                trusted_ca = trusted_certs_path;
            }

            if (trusted_ca == NULL)
            {
                result = __FAILURE__;
            }
            else
            {
                result = put_pki_trusted_cert(g_crypto_store, DEFAULT_TRUSTED_CA_ALIAS, trusted_ca);
            }
        }
        if (trusted_certs_path != NULL)
        {
            free(trusted_certs_path);
        }
        if (device_ca_path != NULL)
        {
            free(device_ca_path);
        }
        if (device_pk_path != NULL)
        {
            free(device_pk_path);
        }
    }

    return result;
}

static CERT_INFO_HANDLE get_cert_info_by_alias(HSM_CLIENT_STORE_HANDLE handle, const char* alias)
{
    CERT_INFO_HANDLE result;

    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle value");
        result = NULL;
    }
    else if (alias == NULL)
    {
        LOG_ERROR("Invalid alias value");
        result = NULL;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = NULL;
    }
    else
    {
        STORE_ENTRY_PKI_CERT *cert_entry;
        CRYPTO_STORE *store = (CRYPTO_STORE*)handle;
        if ((cert_entry = get_pki_cert(store, alias)) == NULL)
        {
            LOG_ERROR("Could not find certificate for %s", alias);
            result = NULL;
        }
        else
        {
            result = prepare_cert_info_handle(store, cert_entry);
        }
    }

    return result;
}

static int remove_cert_by_alias(HSM_CLIENT_STORE_HANDLE handle, const char* alias)
{
    int result;
    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle value");
        result = __FAILURE__;
    }
    else if ((alias == NULL) || (strlen(alias) == 0))
    {
        LOG_ERROR("Invalid alias value");
        result = __FAILURE__;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = __FAILURE__;
    }
    else
    {
        result = remove_if_cert_and_key_exist_by_alias((CRYPTO_STORE*)handle, alias);
    }

    return result;
}

CERT_INFO_HANDLE edge_hsm_client_store_get_pki_cert
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* alias
)
{
    CERT_INFO_HANDLE result = get_cert_info_by_alias(handle, alias);

    if (result == NULL)
    {
        LOG_ERROR("Could not obtain certificate info handle for alias: %s", alias);
    }

    return result;
}

int edge_hsm_client_store_remove_pki_cert(HSM_CLIENT_STORE_HANDLE handle, const char* alias)
{
    return remove_cert_by_alias(handle, alias);
}

static int verify_certificate_helper
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char *alias,
    const char *issuer_alias,
    const char *cert_file_path,
    const char *key_file_path,
    bool *cert_verified
)
{
    int result;
    int cmp = strcmp(alias, issuer_alias);

    if (cmp == 0)
    {
        result = verify_certificate(cert_file_path, key_file_path, cert_file_path, cert_verified);
    }
    else
    {
        STRING_HANDLE issuer_cert_path_handle = NULL;
        CRYPTO_STORE *store = (CRYPTO_STORE*)handle;
        STORE_ENTRY_PKI_CERT *cert_entry;

        const char *issuer_cert_path = NULL;
        if ((cert_entry = get_pki_cert(store, issuer_alias)) != NULL)
        {
            LOG_DEBUG("Certificate already loaded in store for alias %s", issuer_alias);
            issuer_cert_path = STRING_c_str(cert_entry->cert_file);
        }
        else
        {
            if ((issuer_cert_path_handle = STRING_new()) == NULL)
            {
                LOG_ERROR("Could not construct string handle to hold the certificate");
            }
            else if (build_cert_file_paths(issuer_alias, issuer_cert_path_handle, NULL) != 0)
            {
                LOG_ERROR("Could not create file paths to issuer certificate alias %s", issuer_alias);
            }
            else
            {
                issuer_cert_path = STRING_c_str(issuer_cert_path_handle);
            }
        }

        if ((issuer_cert_path == NULL) || !is_file_valid(issuer_cert_path))
        {
            LOG_ERROR("Could not find issuer certificate file %s", issuer_cert_path);
            result = __FAILURE__;
        }
        else if (verify_certificate(cert_file_path, key_file_path, issuer_cert_path, cert_verified) != 0)
        {
            LOG_ERROR("Error trying to verify certificate %s for alias %s", cert_file_path, alias);
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }

        if (issuer_cert_path_handle != NULL)
        {
            STRING_delete(issuer_cert_path_handle);
        }
    }

    return result;
}

static int edge_hsm_client_store_insert_pki_cert
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char *alias,
    const char *issuer_alias,
    const char *cert_file_path,
    const char *key_file_path
)
{
    CRYPTO_STORE *store = (CRYPTO_STORE*)handle;
    int result = put_pki_cert(store, alias, issuer_alias, cert_file_path, key_file_path);
    if (result != 0)
    {
        LOG_ERROR("Could not put PKI certificate and key into the store for %s", alias);
    }

    return result;
}

static int edge_hsm_client_store_create_pki_cert_internal
(
    HSM_CLIENT_STORE_HANDLE handle,
    CERT_PROPS_HANDLE cert_props_handle,
    int ca_path_len
)
{
    int result;
    const char* alias;
    const char* issuer_alias;

    if ((alias = get_alias(cert_props_handle)) == NULL)
    {
        LOG_ERROR("Invalid certificate alias value");
        result = __FAILURE__;
    }
    else if ((issuer_alias = get_issuer_alias(cert_props_handle)) == NULL)
    {
        LOG_ERROR("Invalid certificate alias value");
        result = __FAILURE__;
    }
    else
    {
        STRING_HANDLE alias_cert_handle = NULL;
        STRING_HANDLE alias_pk_handle = NULL;

        if (((alias_cert_handle = STRING_new()) == NULL) ||
            ((alias_pk_handle = STRING_new()) == NULL))
        {
            LOG_ERROR("Could not allocate string handles for storing certificate and key paths");
            result = __FAILURE__;
        }
        else if (build_cert_file_paths(alias, alias_cert_handle, alias_pk_handle) != 0)
        {
            LOG_ERROR("Could not create file paths to the certificate and private key for alias %s", alias);
            result = __FAILURE__;
        }
        else
        {
            CRYPTO_STORE *store = (CRYPTO_STORE*)handle;
            const char *issuer_pk_path = NULL;
            const char *issuer_cert_path = NULL;
            const char *alias_pk_path = STRING_c_str(alias_pk_handle);
            const char *alias_cert_path = STRING_c_str(alias_cert_handle);
            result = 0;
            if (strcmp(alias, issuer_alias) != 0)
            {
                // not a self signed certificate request
                STORE_ENTRY_PKI_CERT *issuer_cert_entry;
                if ((issuer_cert_entry = get_pki_cert(store, issuer_alias)) == NULL)
                {
                    LOG_ERROR("Could not get certificate entry for issuer %s", issuer_alias);
                    result = __FAILURE__;
                }
                else
                {
                    issuer_cert_path = STRING_c_str(issuer_cert_entry->cert_file);
                    issuer_pk_path = STRING_c_str(issuer_cert_entry->private_key_file);
                    if ((issuer_pk_path == NULL) || (issuer_cert_path == NULL))
                    {
                        LOG_ERROR("Unexpected NULL file paths found for issuer %s", issuer_alias);
                        result = __FAILURE__;
                    }
                }
            }
            if (result == 0)
            {
                // @note this will overwrite the older the certificate and private key
                // files for the requested alias
                result = generate_pki_cert_and_key(cert_props_handle,
                                                   rand(), // todo check if rand is okay or if we need something stronger like a SHA1
                                                   ca_path_len,
                                                   alias_pk_path,
                                                   alias_cert_path,
                                                   issuer_pk_path,
                                                   issuer_cert_path);
            }

            if (result != 0)
            {
                LOG_ERROR("Could not create PKI certificate and key for %s", alias);
            }
            else
            {
                result = put_pki_cert(store, alias, issuer_alias, alias_cert_path, alias_pk_path);
                if (result != 0)
                {
                    LOG_ERROR("Could not put PKI certificate and key into the store for %s", alias);
                }
            }
        }
        if (alias_cert_handle)
        {
            STRING_delete(alias_cert_handle);
        }
        if (alias_pk_handle)
        {
            STRING_delete(alias_pk_handle);
        }
    }
    return result;
}

int edge_hsm_client_store_create_pki_cert
(
    HSM_CLIENT_STORE_HANDLE handle,
    CERT_PROPS_HANDLE cert_props_handle
)
{
    int result;
    const char* alias;
    const char* issuer_alias;

    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle value");
        result = __FAILURE__;
    }
    else if (cert_props_handle == NULL)
    {
        LOG_ERROR("Invalid certificate properties value");
        result = __FAILURE__;
    }
    else if ((alias = get_alias(cert_props_handle)) == NULL)
    {
        LOG_ERROR("Invalid certificate alias value");
        result = __FAILURE__;
    }
    else if ((issuer_alias = get_issuer_alias(cert_props_handle)) == NULL)
    {
        LOG_ERROR("Invalid certificate alias value");
        result = __FAILURE__;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = __FAILURE__;
    }
    else
    {
        int load_status = load_if_cert_and_key_exist_by_alias(handle, alias, issuer_alias);
        if (load_status == LOAD_ERR_FAILED)
        {
            LOG_ERROR("Could not check and load certificate and key for alias %s", alias);
            result = __FAILURE__;
        }
        else if (load_status == LOAD_ERR_VERIFICATION_FAILED)
        {
            LOG_ERROR("Failed certificate validation for alias %s", alias);
            result = __FAILURE__;
        }
        else if (load_status == LOAD_ERR_NOT_FOUND)
        {
            LOG_INFO("Generating certificate and key for alias %s", alias);
            if (edge_hsm_client_store_create_pki_cert_internal(handle, cert_props_handle, 0) != 0)
            {
                LOG_ERROR("Could not create certificate and key for alias %s", alias);
                result = __FAILURE__;
            }
            else
            {
                result = 0;
            }
        }
        else
        {
            result = 0;
        }
    }

    return result;
}

int edge_hsm_client_store_insert_pki_trusted_cert
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* alias,
    const char* cert_file_name
)
{
    int result;
    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle value");
        result = __FAILURE__;
    }
    else if (alias == NULL)
    {
        LOG_ERROR("Invalid certificate alias value");
        result = __FAILURE__;
    }
    else if ((cert_file_name == NULL) || (!is_file_valid(cert_file_name)))
    {
        LOG_ERROR("Invalid certificate file name %s", cert_file_name);
        result = __FAILURE__;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = __FAILURE__;
    }
    else
    {
        result = put_pki_trusted_cert(handle, alias, cert_file_name);
    }

    return result;
}

CERT_INFO_HANDLE edge_hsm_client_store_get_pki_trusted_certs
(
	HSM_CLIENT_STORE_HANDLE handle
)
{
    CERT_INFO_HANDLE result;
    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle value");
        result = NULL;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = NULL;
    }
    else
    {
        result = prepare_trusted_certs_info((CRYPTO_STORE*)handle);
    }
    return result;
}

int edge_hsm_client_store_remove_pki_trusted_cert
(
	HSM_CLIENT_STORE_HANDLE handle,
    const char *alias
)
{
    int result;

    if (handle == NULL)
    {
        LOG_ERROR("Invalid handle value");
        result = __FAILURE__;
    }
    else if ((alias == NULL) || (strlen(alias) == 0))
    {
        LOG_ERROR("Invalid handle alias value");
        result = __FAILURE__;
    }
    else if (g_hsm_state != HSM_STATE_PROVISIONED)
    {
        LOG_ERROR("HSM store has not been provisioned");
        result = __FAILURE__;
    }
    else
    {
        result = remove_pki_trusted_cert((CRYPTO_STORE*)handle, alias);
    }

    return result;
}
