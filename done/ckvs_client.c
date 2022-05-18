/**
 * @file ckvs_client.c
 * @brief c.f. ckvs_client.h
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <json-c/json.h>
#include "ckvs_rpc.h"
#include "ckvs_utils.h"
#include "ckvs_io.h"
#include "ckvs.h"
#include "util.h"
#include "ckvs_crypto.h"
#include "ckvs_local.h"
#include <openssl/hmac.h>

// ----------------------------------------------------------------------
/**
 * @brief To get the usable string associated to the key from a json object.
 *
 * @param obj (const json_object*) the json object we retrieve the information from
 * @param key (const char*) the key of the string of interest
 * @param buf (char*) buffer used to store the computed string
 * @return int, error code
 */
static int get_string(const struct json_object *obj, const char *key, char *buf) {
    //check pointers
    if (obj == NULL || key == NULL || buf == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //get the right json object
    struct json_object *value = NULL;
    if (!json_object_object_get_ex(obj, key, &value)) {
        pps_printf("%s %s\n", "An error occurred : did not find the key", key);
        return ERR_IO;
    }

    //get the string from the json object
    const char *string_from_obj = json_object_get_string(value);
    if (string_from_obj == NULL) {
        //error
        return ERR_IO;
    }

    //copy in the buffer
    strcpy(buf, string_from_obj);

    return ERR_NONE;
}

// ----------------------------------------------------------------------
/**
 * @brief To get the integer associated to the key from a json object.
 *
 * @param obj (const json_object*) the json object we retrieve the information from
 * @param key (const char*) the key of the integer of interest
 * @param buf (char*) buffer used to store the computed integer
 * @return int, error code
 */
static int get_int(const struct json_object *obj, const char *key, int *buf) {
    //check pointers
    if (obj == NULL || key == NULL || buf == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    struct json_object *value = NULL;
    if (!json_object_object_get_ex(obj, key, &value)) {
        pps_printf("%s %s", "An error occured : did not find the key", key);
        return ERR_IO;
    }

    //assign to the buffer the value found
    *buf = json_object_get_int(value);

    return ERR_NONE;
}

// ----------------------------------------------------------------------
int ckvs_client_stats(const char *url, int optargc, _unused char **optargv) {
    if (optargc > 0) {
        //error
        return ERR_TOO_MANY_ARGUMENTS;
    }

    //check if the pointer is valid
    if (url == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialiaze the struct ckvs_connection
    ckvs_connection_t conn;
    memset(&conn, 0, sizeof(ckvs_connection_t));

    //initialiaze the struct ckvs
    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(struct CKVS));

    //initialize the connection and check errors
    int err = ckvs_rpc_init(&conn, (const char *) url);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //send an HTTP GET request to the server with command 'stats'
    err = ckvs_rpc(&conn, "stats");
    if (err != ERR_NONE) {
        //error
        ckvs_rpc_close(&conn);
        return err;
    }

    //retrieve the json object
    struct json_object *root_obj = json_tokener_parse(conn.resp_buf);
    if (root_obj == NULL) {
        //error
        pps_printf("%s\n", "An error occured when parsing the string into a json object");
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }

    //retrieve the ckvs from the json object
    err = retrieve_ckvs_from_json(&ckvs, root_obj);
    if (err != ERR_NONE) {
        //error
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        json_object_put(root_obj);
        return err;
    }

    //print the content downloaded from the server
    print_header(&(ckvs.header));

    //print the key of the entries
    for (size_t i = 0; i < ckvs.header.table_size; ++i) {
        if (strlen(ckvs.entries[i].key) != 0) {
            pps_printf("%s       : " STR_LENGTH_FMT(CKVS_MAXKEYLEN) "\n", "Key", ckvs.entries[i].key);
        }
    }

    //free the struct JSON
    err = json_object_put(root_obj);
    if (err != 1) {
        //error
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return ERR_TIMEOUT;
    }

    //close the connection
    ckvs_rpc_close(&conn);

    //free pointers
    ckvs_close(&ckvs);

    return ERR_NONE;
}

// ----------------------------------------------------------------------
int ckvs_client_get(const char *url, int optargc, char **optargv) {
    if (optargc < 2) return ERR_NOT_ENOUGH_ARGUMENTS;
    if (optargc > 2) return ERR_TOO_MANY_ARGUMENTS;

    const char *key = optargv[0];
    const char *pwd = optargv[1];

    //check if the pointeurs are valid
    if (key == NULL || pwd == NULL || url == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialiaze the struct ckvs_connection
    ckvs_connection_t conn;
    memset(&conn, 0, sizeof(ckvs_connection_t));

    //initialize the struct ckvs_memrecord_t
    ckvs_memrecord_t ckvs_mem;
    memset(&ckvs_mem, 0, sizeof(ckvs_memrecord_t));

    //initialize the connection and check errors
    int err = ckvs_rpc_init(&conn, (const char *) url);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //to generate in particular the auth_key and c1 and store them in ckvs_mem
    err = ckvs_client_encrypt_pwd(&ckvs_mem, key, pwd);
    if (err != ERR_NONE) {
        // error
        ckvs_rpc_close(&conn);
        return err;
    }

    //compute the url escaped key
    char* ready_key = NULL;
    CURL* curl = curl_easy_init();
    if (curl != NULL) {
        ready_key = curl_easy_escape(curl, key, strlen(key));
        if (ready_key == NULL) {
            //error
            ckvs_rpc_close(&conn);
            curl_free(curl);
            return ERR_IO;
        }
        curl_easy_cleanup(curl);
    } else {
        //error
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }

    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&ckvs_mem.auth_key, buffer);

    //build the string for url containing the whole information
    char *page = calloc(SHA256_PRINTED_STRLEN + strlen(ready_key) + 19, sizeof(char));
    if (page == NULL) {
        ckvs_rpc_close(&conn);
        curl_free(ready_key);
        return ERR_OUT_OF_MEMORY;
    }
    strcpy(page, "get?key=");
    strcat(page, ready_key);
    strcat(page, "&auth_key=");
    strncat(page, &buffer, SHA256_PRINTED_STRLEN);

    curl_free(ready_key);

    //send request to server with ready url
    err = ckvs_rpc(&conn, page);
    free(page);
    if (err != ERR_NONE) {
        //error
        ckvs_rpc_close(&conn);
        return err;
    }

    //initialize buffer for c2
    char* c2_str[SHA256_PRINTED_STRLEN + 1];
    ckvs_sha_t* c2 = calloc(1, sizeof(ckvs_sha_t));

    //retrieve the json object
    struct json_object *root_obj = json_tokener_parse(conn.resp_buf);
    if (root_obj == NULL) {
        //error, need to get which one
        if (strncmp(conn.resp_buf, "Error:", 6) == 0) {
            err = get_err(conn.resp_buf + 7);
        }
        pps_printf("%s\n", "An error occured when parsing the string into a json object");
        ckvs_rpc_close(&conn);
        free(c2); c2 = NULL;
        return err == ERR_NONE ? ERR_IO : err;
    }

    //retrieve the hex-encoded string of c2 from json object
    err = get_string(root_obj, "c2", c2_str);
    if (err != ERR_NONE) {
        //error, need to get which one
        char error[30];
        int err2 = get_string(root_obj, "error", error);
        if (err2 == ERR_NONE) {
            err = get_err(error);
        }
        ckvs_rpc_close(&conn);
        free(c2); c2 = NULL;
        json_object_put(root_obj);
        return err;
    }

    //convert the hex-encoded string of c2 into SHA256
    err = SHA256_from_string(c2_str, c2);
    if (err != ERR_NONE) {
        //error
        ckvs_rpc_close(&conn);
        free(c2); c2 = NULL;
        json_object_put(root_obj);
        return err;
    }

    //initialize a buffer for the hex-encoded data
    unsigned char* data = calloc(conn.resp_size + 1, sizeof(unsigned char));
    if (data == NULL) {
        //error
        ckvs_rpc_close(&conn);
        free(c2); c2 = NULL;
        json_object_put(root_obj);
        return ERR_OUT_OF_MEMORY;
    }

    //retrieve the hex-encoded string of data from the json object
    err = get_string(root_obj,"data",data);
    if (err != ERR_NONE) {
        //error
        free(data); data = NULL;
        free(c2); c2 = NULL;
        ckvs_rpc_close(&conn);
        json_object_put(root_obj);
        return err;
    }

    //compute the masterkey
    err = ckvs_client_compute_masterkey(&ckvs_mem, c2);
    if (err != ERR_NONE) {
        //error
        free(data); data = NULL;
        free(c2); c2 = NULL;
        ckvs_rpc_close(&conn);
        json_object_put(root_obj);
        return err;
    }

    //initialize the string where the encrypted secret will be stored
    unsigned char *encrypted = calloc(strlen(data) / 2, sizeof(unsigned char));
    if (encrypted == NULL) {
        //error
        free(data); data = NULL;
        free(c2); c2 = NULL;
        ckvs_rpc_close(&conn);
        json_object_put(root_obj);
        return ERR_OUT_OF_MEMORY;
    }

    //convert the hex-encoded string of data
    err = hex_decode(data,encrypted);
    if (err == -1) {
        //error
        return ERR_IO;
    }

    //initialize the string where the decrypted secret will be stored
    size_t decrypted_len = strlen(data) / 2 + EVP_MAX_BLOCK_LENGTH;
    unsigned char *decrypted = calloc(decrypted_len, sizeof(unsigned char));
    if (decrypted == NULL) {
        //error
        free(data); data = NULL;
        free(c2); c2 = NULL;
        free(encrypted); encrypted = NULL;
        ckvs_rpc_close(&conn);
        json_object_put(root_obj);
        return ERR_OUT_OF_MEMORY;
    }

    //decrypts the string with the secret with in particular the master_key stored in ckvs_mem
    err = ckvs_client_crypt_value(&ckvs_mem, DECRYPTION, encrypted, strlen(data) / 2, decrypted,
                                  &decrypted_len);
    if (err != ERR_NONE) {
        //error
        free(encrypted); encrypted = NULL;
        free(data); data = NULL;
        free(c2); c2 = NULL;
        curl_free(ready_key);
        free_uc(&decrypted);
        json_object_put(root_obj);
        ckvs_rpc_close(&conn);
        return err;
    }

    //check if we have to end the lecture
    for (size_t i = 0; i < decrypted_len; ++i) {
        if ((iscntrl(decrypted[i]) && decrypted[i] != '\n')) break;
        pps_printf("%c", decrypted[i]);
    }

    //free all objects
    free(encrypted); encrypted = NULL;
    free(c2); c2 = NULL;
    free(data); data = NULL;
    json_object_put(root_obj);
    free_uc(&decrypted);
    ckvs_rpc_close(&conn);

    return ERR_NONE;
}

// ----------------------------------------------------------------------
int retrieve_ckvs_header_from_json(struct CKVS *ckvs, const struct json_object *obj) {
    //check pointers
    if (ckvs == NULL || obj == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    char header_str[CKVS_HEADERSTRINGLEN];
    uint32_t infos[CKVS_UINT32_T_ELEMENTS] = {0};

    int err = get_string(obj, "header_string", header_str);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //check that the header starts with the good prefix
    if (strncmp(CKVS_HEADERSTRING_PREFIX, header_str, strlen(CKVS_HEADERSTRING_PREFIX)) != 0) {
        //error
        return ERR_CORRUPT_STORE;
    }

    err = get_int(obj, "version", &infos[0]);
    if (err != ERR_NONE) {
        //error
        return err;
    }
    //check that it is the good version, i.e. 1
    if (infos[0] != 1) {
        //error
        return ERR_CORRUPT_STORE;
    }

    err = get_int(obj, "table_size", &infos[1]);
    if (err != ERR_NONE) {
        //error
        return err;
    }
    //check that the table has a size power of 2
    err = check_pow_2(infos[1]);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    err = get_int(obj, "threshold_entries", &infos[2]);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    err = get_int(obj, "num_entries", &infos[3]);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //construct the header now that every field is safe
    ckvs_header_t header = {
            .version           =infos[0],
            .table_size        =infos[1],
            .threshold_entries =infos[2],
            .num_entries       =infos[3]
    };
    strcpy(header.header_string, header_str);
    ckvs->header = header;

    return ERR_NONE;
}

// ----------------------------------------------------------------------
int retrieve_ckvs_from_json(struct CKVS *ckvs, const struct json_object *obj){

    //check pointers
    if (ckvs == NULL || obj == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    int err = retrieve_ckvs_header_from_json(ckvs, obj);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    struct json_object *keys_json_object = NULL;
    if (!json_object_object_get_ex(obj, "keys", &keys_json_object)) {
        //error
        pps_printf("%s\n", "An error occured : did not find the json array keys");
        return ERR_IO;
    }

    //retrieve the keys of the ckvs entries
    ckvs->entries = calloc(ckvs->header.table_size, sizeof(ckvs_entry_t));
    for (size_t i = 0; i < json_object_array_length(keys_json_object); ++i) {
        struct json_object *temp_obj = json_object_array_get_idx(keys_json_object, i);
        if (temp_obj == NULL) {
            //error
            return ERR_IO;
        }
        strncpy(ckvs->entries[i].key, json_object_get_string(temp_obj), CKVS_MAXKEYLEN);
    }

    return ERR_NONE;
}

/* *************************************************** *
 * TODO WEEK 13                                        *
 * *************************************************** */
int ckvs_client_set(const char *url, int optargc, char **optargv) {
    return NOT_IMPLEMENTED;
}

int ckvs_client_new(const char *url, int optargc, char **optargv) {
    return NOT_IMPLEMENTED;
}
