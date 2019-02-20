#include "edge_hsm_client_store.h"

HSM_STATE_T g_hsm_state = HSM_STATE_UNPROVISIONED;

CRYPTO_STORE* g_crypto_store = NULL;
int g_store_ref_count = 0;

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
