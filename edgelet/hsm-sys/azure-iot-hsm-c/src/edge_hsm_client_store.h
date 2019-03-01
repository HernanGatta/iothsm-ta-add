#ifndef EDGE_HSM_CLIENT_STORE_H
#define EDGE_HSM_CLIENT_STORE_H

#include <limits.h>
#include <stdlib.h>

#include "azure_c_shared_utility/gballoc.h"
#include "azure_c_shared_utility/base64.h"
#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/singlylinkedlist.h"
#include "azure_c_shared_utility/sha.h"

#include "hsm_client_data.h"
#include "hsm_client_store.h"
#include "hsm_constants.h"
#include "hsm_log.h"
#include "hsm_utils.h"

//##############################################################################
// Data types
//##############################################################################
#define OWNER_CA_PATHLEN  3
#define DEVICE_CA_PATHLEN (OWNER_CA_PATHLEN - 1)

#define LOAD_SUCCESS 0
#define LOAD_ERR_NOT_FOUND 1
#define LOAD_ERR_VERIFICATION_FAILED 2
#define LOAD_ERR_FAILED 3

// local normalized file storage defines
#define NUM_NORMALIZED_ALIAS_CHARS  32

struct STORE_ENTRY_KEY_TAG
{
    STRING_HANDLE id;
    BUFFER_HANDLE key;
};
typedef struct STORE_ENTRY_KEY_TAG STORE_ENTRY_KEY;

struct CRYPTO_STORE_ENTRY_TAG
{
    SINGLYLINKEDLIST_HANDLE sas_keys;
    SINGLYLINKEDLIST_HANDLE sym_enc_keys;
    SINGLYLINKEDLIST_HANDLE pki_certs;
    SINGLYLINKEDLIST_HANDLE pki_trusted_certs;
};
typedef struct CRYPTO_STORE_ENTRY_TAG CRYPTO_STORE_ENTRY;

struct CRYPTO_STORE_TAG
{
    STRING_HANDLE id;
    CRYPTO_STORE_ENTRY* store_entry;
    int ref_count;
};
typedef struct CRYPTO_STORE_TAG CRYPTO_STORE;

typedef enum HSM_STATE_TAG_T
{
    HSM_STATE_UNPROVISIONED = 0,
    HSM_STATE_PROVISIONED,
    HSM_STATE_PROVISIONING_ERROR
} HSM_STATE_T;

extern HSM_STATE_T g_hsm_state;

extern CRYPTO_STORE* g_crypto_store;
extern int g_store_ref_count;

//##############################################################################
// Forward declarations
//##############################################################################

int edge_hsm_client_store_create_pki_cert
(
    HSM_CLIENT_STORE_HANDLE handle,
    CERT_PROPS_HANDLE cert_props_handle
);

CERT_INFO_HANDLE edge_hsm_client_store_get_pki_cert
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* alias
);

int edge_hsm_client_store_remove_pki_cert(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* alias
);

int edge_hsm_client_store_insert_pki_trusted_cert
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* alias,
    const char* cert_file_name
);

CERT_INFO_HANDLE edge_hsm_client_store_get_pki_trusted_certs
(
	HSM_CLIENT_STORE_HANDLE handle
);

int edge_hsm_client_store_remove_pki_trusted_cert
(
	HSM_CLIENT_STORE_HANDLE handle,
    const char *alias
);

void destroy_pki_certs
(
    SINGLYLINKEDLIST_HANDLE certs
);

void destroy_pki_trusted_certs
(
    SINGLYLINKEDLIST_HANDLE trusted_certs
);

const char* get_base_dir(void);

int build_cert_file_paths
(
    const char *alias,
    STRING_HANDLE cert_file,
    STRING_HANDLE pk_file
);

int build_enc_key_file_path
(
    const char *key_name,
    STRING_HANDLE key_file
);

int hsm_provision_edge_certificates(void);

KEY_HANDLE edge_hsm_client_open_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    HSM_KEY_T key_type,
    const char* key_name
);

int edge_hsm_client_close_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    KEY_HANDLE key_handle
);

int edge_hsm_client_store_remove_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    HSM_KEY_T key_type,
    const char* key_name
);

int edge_hsm_client_store_insert_sas_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* key_name,
    const unsigned char* key,
    size_t key_size
);

int edge_hsm_client_store_insert_encryption_key
(
    HSM_CLIENT_STORE_HANDLE handle,
    const char* key_name
);

void destroy_keys
(
    SINGLYLINKEDLIST_HANDLE keys
);

#endif //EDGE_HSM_CLIENT_STORE_H
