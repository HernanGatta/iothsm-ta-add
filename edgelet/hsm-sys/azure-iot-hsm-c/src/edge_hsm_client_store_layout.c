#include "edge_hsm_client_store.h"

static STRING_HANDLE compute_b64_sha_digest_string
(
    const unsigned char* ip_buffer,
    size_t ip_buffer_size
)
{
    STRING_HANDLE result;
    USHAContext ctx;
    unsigned char *digest = (unsigned char*)malloc(USHAMaxHashSize);

    if (digest == NULL)
    {
        LOG_ERROR("Could not allocate memory to hold SHA digest");
        result = NULL;
    }
    else if (ip_buffer_size > UINT_MAX)
    {
        LOG_ERROR("Input buffer size too large %zu", ip_buffer_size);
        result = NULL;
    }
    else
    {
        int status;

        memset(digest, 0, USHAMaxHashSize);
        status = USHAReset(&ctx, SHA256) ||
                 USHAInput(&ctx, ip_buffer, (unsigned int)ip_buffer_size) ||
                 USHAResult(&ctx, digest);
        if (status != shaSuccess)
        {
            LOG_ERROR("Computing SHA digest failed %d", status);
            result = NULL;
        }
        else
        {
            size_t digest_size = USHAHashSize(SHA256);
            if ((result = Base64_Encode_Bytes(digest, digest_size)) == NULL)
            {
                LOG_ERROR("Base 64 encode failed after SHA compute");
            }
            else
            {
                // stanford base64 URL replace plus encoding = to _
                (void)STRING_replace(result, '+', '-');
                (void)STRING_replace(result, '/', '_');
                (void)STRING_replace(result, '=', '_');
            }
        }
        free(digest);
    }

    return result;
}

static int make_new_dir_relative_to_dir(const char *relative_dir, const char *new_dir_name)
{
    int result;

    STRING_HANDLE dir_path = STRING_construct(relative_dir);
    if (dir_path == NULL)
    {
        LOG_ERROR("Could not construct handle to relative dir %s", relative_dir);
        result = __FAILURE__;
    }
    else
    {
        if ((STRING_concat(dir_path, SLASH) != 0) ||
            (STRING_concat(dir_path, new_dir_name) != 0))
        {
            LOG_ERROR("Could not construct handle to relative dir %s", relative_dir);
            result = __FAILURE__;
        }
        else if (make_dir(STRING_c_str(dir_path)) != 0)
        {
            LOG_ERROR("Could not create dir %s relative to %s", new_dir_name, relative_dir);
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }

        STRING_delete(dir_path);
    }

    return result;
}

static const char* obtain_default_platform_base_dir(void)
{
    const char *result;
    static STRING_HANDLE PLATFORM_BASE_PATH = NULL;

    if (PLATFORM_BASE_PATH == NULL)
    {
        #if defined __WINDOWS__ || defined _WIN32 || defined _WIN64 || defined _Windows
            STRING_HANDLE path;
            char *env_base_path = NULL;

            if (hsm_get_env(DEFAULT_EDGE_BASE_DIR_ENV_WIN, &env_base_path) != 0)
            {
                LOG_ERROR("Error obtaining Windows env variable %s", DEFAULT_EDGE_HOME_DIR_WIN);
                result = NULL;
            }
            else if (env_base_path == NULL)
            {
                LOG_ERROR("Windows env variable %s is not set", DEFAULT_EDGE_HOME_DIR_WIN);
                result = NULL;
            }
            else if (!is_directory_valid(env_base_path))
            {
                LOG_ERROR("Dir set in environment variable %s is not valid", env_base_path);
                result = NULL;
            }
            else if ((path = STRING_construct(env_base_path)) == NULL)
            {
                LOG_ERROR("Could not create string handle for default base path");
                result = NULL;
            }
            else
            {
                if ((STRING_concat(path, SLASH) != 0) ||
                    (STRING_concat(path, DEFAULT_EDGE_HOME_DIR_WIN) != 0))
                {
                    LOG_ERROR("Could not build path to IoT Edge home dir");
                    STRING_delete(path);
                    result = NULL;
                }
                else
                {
                    result = STRING_c_str(path);
                    if (make_dir(result) != 0)
                    {
                        LOG_ERROR("Could not create home dir %s", result);
                        STRING_delete(path);
                        result = NULL;
                    }
                    else
                    {
                        PLATFORM_BASE_PATH = path;
                    }
                }
            }
            if (env_base_path != NULL)
            {
                free(env_base_path);
                env_base_path = NULL;
            }
        #else
            if (make_dir(DEFAULT_EDGE_HOME_DIR_UNIX) != 0)
            {
                LOG_ERROR("Could not create home dir %s", DEFAULT_EDGE_HOME_DIR_UNIX);
                result = NULL;
            }
            else if ((PLATFORM_BASE_PATH = STRING_construct(DEFAULT_EDGE_HOME_DIR_UNIX)) == NULL)
            {
                LOG_ERROR("Could not create string handle for default base path");
                result = NULL;
            }
            else
            {
                result = DEFAULT_EDGE_HOME_DIR_UNIX;
            }
        #endif
    }
    else
    {
        // platform base dir already initialized
        result = STRING_c_str(PLATFORM_BASE_PATH);
    }

    return result;
}

const char* get_base_dir(void)
{
    static STRING_HANDLE base_dir_path = NULL;

    const char *result = NULL;
    if (base_dir_path == NULL)
    {
        int status = 0;
        if ((base_dir_path = STRING_new()) == NULL)
        {
            LOG_ERROR("Could not allocate memory to hold hsm base dir");
            status = __FAILURE__;
        }
        else
        {
            char* env_base_path = NULL;
            if (hsm_get_env(ENV_EDGE_HOME_DIR, &env_base_path) != 0)
            {
                LOG_ERROR("Could not lookup home dir env variable %s", ENV_EDGE_HOME_DIR);
                status = __FAILURE__;
            }
            else if ((env_base_path != NULL) && (strlen(env_base_path) != 0))
            {
                if (!is_directory_valid(env_base_path))
                {
                    LOG_ERROR("Directory path in env variable %s is invalid. Found %s",
                              ENV_EDGE_HOME_DIR, env_base_path);
                    status = __FAILURE__;
                }
                else
                {
                    status = STRING_concat(base_dir_path, env_base_path);
                }
            }
            else
            {
                const char* default_dir = obtain_default_platform_base_dir();
                if (default_dir == NULL)
                {
                    LOG_ERROR("IOTEDGED platform specific default base directory is invalid");
                    status = __FAILURE__;
                }
                else if (STRING_concat(base_dir_path, default_dir) != 0)
                {
                    LOG_ERROR("Could not construct path to HSM dir");
                    status = __FAILURE__;
                }
            }
            if (env_base_path != NULL)
            {
                free(env_base_path);
                env_base_path = NULL;
            }
            if (status == 0)
            {
                if ((STRING_concat(base_dir_path, SLASH) != 0) ||
                    (STRING_concat(base_dir_path, HSM_CRYPTO_DIR) != 0))
                {
                    LOG_ERROR("Could not construct path to HSM dir");
                    status = __FAILURE__;
                }
                else
                {
                    result = STRING_c_str(base_dir_path);
                    if (make_dir(result) != 0)
                    {
                        LOG_ERROR("Could not make HSM dir %s", result);
                        status = __FAILURE__;
                        result = NULL;
                    }
                    else
                    {
                        // make the certs and keys dirs
                        if (make_new_dir_relative_to_dir(result, CERTS_DIR) != 0)
                        {
                            LOG_ERROR("Could not make HSM certs dir under %s", result);
                            status = __FAILURE__;
                            result = NULL;
                        }
                        else if (make_new_dir_relative_to_dir(result, CERT_KEYS_DIR) != 0)
                        {
                            LOG_ERROR("Could not make HSM cert keys dir under %s", result);
                            status = __FAILURE__;
                            result = NULL;
                        }
                        else if (make_new_dir_relative_to_dir(result, ENC_KEYS_DIR) != 0)
                        {
                            LOG_ERROR("Could not make HSM encryption keys dir under %s", result);
                            status = __FAILURE__;
                            result = NULL;
                        }
                    }
                }
            }
        }
        if ((status != 0) && (base_dir_path != NULL))
        {
            STRING_delete(base_dir_path);
            base_dir_path = NULL;
        }
    }
    else
    {
        result = STRING_c_str(base_dir_path);
    }

    return result;
}

static STRING_HANDLE normalize_alias_file_path(const char *alias)
{
    STRING_HANDLE result;
    STRING_HANDLE alias_sha = NULL;
    size_t alias_len = strlen(alias);

    if ((result = STRING_new()) == NULL)
    {
        LOG_ERROR("Could not allocate normalized file string handle");
    }
    else if ((alias_sha = compute_b64_sha_digest_string((unsigned char*)alias, alias_len)) == NULL)
    {
        LOG_ERROR("Could not compute SHA for normalizing %s", alias);
        STRING_delete(result);
        result = NULL;
    }
    else
    {
        size_t idx = 0, norm_alias_idx = 0;
        char norm_alias[NUM_NORMALIZED_ALIAS_CHARS + 1];

        memset(norm_alias, 0, sizeof(norm_alias));
        while ((norm_alias_idx < NUM_NORMALIZED_ALIAS_CHARS) && (idx < alias_len))
        {
            char c = alias[idx];
            if (((c >= 'A') && (c <= 'Z')) ||
                ((c >= 'a') && (c <= 'z')) ||
                ((c >= '0') && (c <= '9')) ||
                (c == '_') || (c == '-'))
            {
                norm_alias[norm_alias_idx] = c;
                norm_alias_idx++;
            }
            idx++;
        }

        if ((STRING_concat(result, norm_alias) != 0) ||
            (STRING_concat_with_STRING(result, alias_sha) != 0))
        {
            LOG_ERROR("Could not construct normalized path for %s", alias);
            STRING_delete(result);
            result = NULL;
        }
    }

    if (alias_sha != NULL)
    {
        STRING_delete(alias_sha);
    }

    return result;
}

int build_cert_file_paths(const char *alias, STRING_HANDLE cert_file, STRING_HANDLE pk_file)
{
    int result;
    const char *base_dir_path = get_base_dir();
    STRING_HANDLE normalized_alias;

    if ((normalized_alias = normalize_alias_file_path(alias)) == NULL)
    {
        LOG_ERROR("Could not normalize path to certificate and key for %s", alias);
        result = __FAILURE__;
    }
    else
    {
        if ((STRING_concat(cert_file, base_dir_path) != 0) ||
            (STRING_concat(cert_file, SLASH)  != 0) ||
            (STRING_concat(cert_file, CERTS_DIR)  != 0) ||
            (STRING_concat(cert_file, SLASH)  != 0) ||
            (STRING_concat_with_STRING(cert_file, normalized_alias) != 0) ||
            (STRING_concat(cert_file, CERT_FILE_EXT) != 0))
        {
            LOG_ERROR("Could not construct path to certificate for %s", alias);
            result = __FAILURE__;
        }
        else if ((pk_file != NULL) &&
                 ((STRING_concat(pk_file, base_dir_path) != 0) ||
                  (STRING_concat(pk_file, SLASH)  != 0) ||
                  (STRING_concat(pk_file, CERT_KEYS_DIR)  != 0) ||
                  (STRING_concat(pk_file, SLASH)  != 0) ||
                  (STRING_concat_with_STRING(pk_file, normalized_alias) != 0) ||
                  (STRING_concat(pk_file, PK_FILE_EXT) != 0)))
        {
            LOG_ERROR("Could not construct path to private key for %s", alias);
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
        STRING_delete(normalized_alias);
    }

    return result;
}

int build_enc_key_file_path(const char *key_name, STRING_HANDLE key_file)
{
    int result;
    const char *base_dir_path = get_base_dir();
    STRING_HANDLE normalized_alias;

    if ((normalized_alias = normalize_alias_file_path(key_name)) == NULL)
    {
        LOG_ERROR("Could not normalize path to encryption key for %s", key_name);
        result = __FAILURE__;
    }
    else
    {
        if ((STRING_concat(key_file, base_dir_path) != 0) ||
            (STRING_concat(key_file, SLASH)  != 0) ||
            (STRING_concat(key_file, ENC_KEYS_DIR)  != 0) ||
            (STRING_concat(key_file, SLASH)  != 0) ||
            (STRING_concat_with_STRING(key_file, normalized_alias) != 0) ||
            (STRING_concat(key_file, ENC_KEY_FILE_EXT) != 0))
        {
            LOG_ERROR("Could not construct path to save key for %s", key_name);
            result = __FAILURE__;
        }
        else
        {
            result = 0;
        }
        STRING_delete(normalized_alias);
    }

    return result;
}
