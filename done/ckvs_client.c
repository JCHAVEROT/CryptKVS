/**
 * @file ckvs_client.c
 * @brief c.f. ckvs_client.h
 */
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <json-c/json.h>
#include "ckvs_rpc.h"
#include "ckvs_utils.h"
#include "ckvs_io.h"
#include "ckvs_client.h"
#include "ckvs.h"
#include "util.h"
#include "ckvs_crypto.h"
#include "ckvs_local.h"
#include <openssl/hmac.h>
#include "openssl/rand.h"

/**
 * @brief For the SET command, default name for the file to reconstruct
 */
#define DEFAULT_NAME "data.json"

/**
 * @brief For the SET command, default offset for the file to reconstruct
 */
#define DEFAULT_OFFSET "0"

// ======================================================================
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

    //initialize the struct ckvs_connection
    ckvs_connection_t conn;
    memset(&conn, 0, sizeof(ckvs_connection_t));

    //initialize the struct ckvs
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
        return ERR_IO;
    }

    //close the connection
    ckvs_rpc_close(&conn);

    //free pointers
    ckvs_close(&ckvs);

    return ERR_NONE;
}

// ======================================================================
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

    //call the modularize getset function with NULL as set_value
    return ckvs_client_getset(url, key, pwd, NULL);
}

// ======================================================================
int retrieve_ckvs_header_from_json(struct CKVS *ckvs, const struct json_object *obj) {
    //check pointers
    if (ckvs == NULL || obj == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    char header_str[CKVS_HEADERSTRINGLEN];
    uint32_t infos[CKVS_UINT32_T_ELEMENTS] = {0};

    //retrieve the header string
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

    //retrieve the version
    err = get_int(obj, "version", (int *) &infos[0]);
    if (err != ERR_NONE) {
        //error
        return err;
    }
    //check that it is the good version, i.e. 1
    if (infos[0] != 1) {
        //error
        return ERR_CORRUPT_STORE;
    }

    //retrieve the table size
    err = get_int(obj, "table_size", (int *) &infos[1]);
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

    //retrieve the number of threshold entries
    err = get_int(obj, "threshold_entries", (int *) &infos[2]);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //retrieve the number of entries
    err = get_int(obj, "num_entries", (int *) &infos[3]);
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

// ======================================================================
int retrieve_ckvs_from_json(struct CKVS *ckvs, const struct json_object *obj) {
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
    if (optargc < 3) return ERR_NOT_ENOUGH_ARGUMENTS;
    if (optargc > 3) return ERR_TOO_MANY_ARGUMENTS;

    const char *key = optargv[0];
    const char *pwd = optargv[1];
    const char *filename = optargv[2];

    //check pointers
    if (url == NULL || key == NULL || pwd == NULL || filename == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialize buffer and its size
    char *buffer = NULL;
    size_t buffer_size = 0;

    //read file called filename and prints it in the buffer and check errors
    int err = read_value_file_content(filename, &buffer, &buffer_size);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //called the modularized function ckvs_client_getset with the buffer
    err = ckvs_client_getset(url, key, pwd, buffer);

    //free the buffer
    free(buffer);
    buffer = NULL;
    buffer_size = 0;

    return err;
}

// ======================================================================
int ckvs_client_getset(const char *url, const char *key, const char *pwd, const char *set_value) {
    //check pointers
    if (url == NULL || key == NULL || pwd == NULL) {
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
    int err = ckvs_rpc_init(&conn, url);
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
    char *ready_key = NULL;
    CURL *curl = curl_easy_init();
    if (curl != NULL) {
        ready_key = curl_easy_escape(curl, key, (int) strlen(key));
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
    char *page = calloc(SHA256_PRINTED_STRLEN + strlen(ready_key) + 41 + 1, sizeof(char));
    if (page == NULL) {
        ckvs_rpc_close(&conn);
        curl_free(ready_key);
        return ERR_OUT_OF_MEMORY;
    }
    (set_value == NULL)
    ? strcat(page, "g") //the get part
    : strcat(page, "s"); //the set part
    strcat(page, "et?key=");
    strcat(page, ready_key);
    strcat(page, "&auth_key=");
    strncat(page, buffer, SHA256_PRINTED_STRLEN);

    curl_free(ready_key);

    err = (set_value == NULL)
          ? do_client_get(&conn, &ckvs_mem, page) //the get part
          : do_client_set(&conn, &ckvs_mem, page, set_value); //the set part

    //close the connection
    free(page); page = NULL;
    ckvs_rpc_close(&conn);

    return err;
}

// ======================================================================
int do_client_get(struct ckvs_connection *conn, ckvs_memrecord_t *ckvs_mem, char *url) {
    //check pointers
    if (conn == NULL || ckvs_mem == NULL || url == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //send request to server with ready url
    int err = ckvs_rpc(conn, url);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //initialize buffer for c2
    char c2_str[SHA256_PRINTED_STRLEN];
    struct ckvs_sha c2;

    //retrieve the json object
    struct json_object *root_obj = json_tokener_parse(conn->resp_buf);
    if (root_obj == NULL) {
        //error, need to get which one
        if (strncmp(conn->resp_buf, "Error:", 6) == 0) {
            err = get_err(conn->resp_buf + 7);
        }
        pps_printf("%s\n", "An error occured when parsing the string into a json object");
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
        json_object_put(root_obj);
        return err;
    }

    //convert the hex-encoded string of c2 into SHA256
    err = SHA256_from_string(c2_str, &c2);
    if (err != ERR_NONE) {
        //error
        json_object_put(root_obj);
        return err;
    }

    //compute the masterkey
    err = ckvs_client_compute_masterkey(ckvs_mem, &c2);
    if (err != ERR_NONE) {
        //error
        json_object_put(root_obj);
        return err;
    }

    //get the hex-encoded data
    //note: not using the get_string function from ckvs_utils.c because the data is of unknown length
    struct json_object *data_json_obj = NULL;
    if (!json_object_object_get_ex(root_obj, "data", &data_json_obj)) {
        //error
        pps_printf("%s %s\n", "An error occurred : did not find the key", "data");
        json_object_put(root_obj);
        return ERR_IO;
    }

    //retrieve the hex-encoded string of data from the json object
    const char *data_hex = json_object_get_string(data_json_obj);
    json_object_put(root_obj);
    if (data_hex == NULL) {
        //error
        return ERR_IO;
    }

    //initialize the string where the encrypted secret will be stored
    unsigned char *encrypted = calloc(strlen(data_hex) / 2 + 2, sizeof(unsigned char)); //because for a hex-string of length L being odd, its hex-decoded string will be of length (L/2)+1
    if (encrypted == NULL) {
        //error
        return ERR_OUT_OF_MEMORY;
    }

    //convert the hex-encoded string of data
    int decoded_size = hex_decode(data_hex, encrypted);
    if (decoded_size == -1) {
        //error
        return ERR_IO;
    }

    //initialize the string where the decrypted secret will be stored
    size_t decrypted_len = (size_t) decoded_size + EVP_MAX_BLOCK_LENGTH + 1;
    unsigned char *decrypted = calloc(decrypted_len, sizeof(unsigned char));
    if (decrypted == NULL) {
        //error
        free(encrypted); encrypted = NULL;
        return ERR_OUT_OF_MEMORY;
    }

    //decrypt the string with the secret with in particular the master_key stored in ckvs_mem
    err = ckvs_client_crypt_value(ckvs_mem, DECRYPTION, encrypted, (size_t) decoded_size, decrypted,
                                  &decrypted_len);
    if (err != ERR_NONE) {
        //error
        free(encrypted); encrypted = NULL;
        free_uc(&decrypted);
        return err;
    }

    //print the decrypted secret abd check if we have to end the lecture
    for (size_t i = 0; i < decrypted_len; ++i) {
        if ((iscntrl(decrypted[i]) && decrypted[i] != '\n')) break;
        pps_printf("%c", decrypted[i]);
    }

    //free all objects
    free(encrypted); encrypted = NULL;
    free_uc(&decrypted);

    return ERR_NONE;
}

// ======================================================================
int do_client_set(struct ckvs_connection *conn, ckvs_memrecord_t *ckvs_mem, char *url, const char *set_value) {
    //check pointers
    if (conn == NULL || ckvs_mem == NULL || url == NULL || set_value == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialize and generate randomly SHA256 of c2 so not to decrease entropy
    struct ckvs_sha c2;
    int err = RAND_bytes((unsigned char *) c2.sha, SHA256_DIGEST_LENGTH);
    if (err != 1) {
        //error
        return ERR_IO;
    }

    //now we have the necessary variables, compute the masterkey
    err = ckvs_client_compute_masterkey(ckvs_mem, &c2);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //encode the new value to be set
    unsigned char *encrypted = NULL;
    size_t encrypted_length = 0;
    err = encrypt_secret(ckvs_mem, set_value, &encrypted, &encrypted_length);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //prepare the url for the request: name and offset need to be added
    strcat(url, "&name=");
    strcat(url, DEFAULT_NAME);
    strcat(url, "&offset=");
    strcat(url, DEFAULT_OFFSET);

    //construction of the POST from the encoded secret
    //hex-encoding of c2
    char c2_hex[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&c2, c2_hex);

    //hex-encoding of the encrypted secret
    char* encrypted_hex = calloc(encrypted_length * 2 + 1, sizeof(char));
    if (encrypted_hex == NULL) {
        //error
        free_sve(&encrypted, &encrypted_length);
        return ERR_OUT_OF_MEMORY;
    }

    hex_encode(encrypted, encrypted_length, encrypted_hex);
    free_sve(&encrypted, &encrypted_length);

    //create the new json object
    struct json_object *object = json_object_new_object();
    if (object == NULL) {
        //error
        free(encrypted_hex); encrypted_hex = NULL;
        return ERR_OUT_OF_MEMORY;
    }

    //add the c2 hex-encoded string to the json
    err = add_string(object, "c2", c2_hex);
    if (err != ERR_NONE) {
        //error
        free(encrypted_hex); encrypted_hex = NULL;
        json_object_put(object);
        return err;
    }

    //add the data hex-encoded and encrypted string to the json
    err = add_string(object, "data", encrypted_hex);
    free(encrypted_hex); encrypted_hex = NULL;
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        return err;
    }

    //serialize the json onject
    size_t length = 0;
    const char *json_string = json_object_to_json_string_length(object, JSON_C_TO_STRING_PRETTY, &length);
    json_object_put(object);

    //create the post with the null character at the end
    char* post = calloc(length + 1, sizeof(char));
    if (post == NULL) {
        //error
        return ERR_OUT_OF_MEMORY;
    }
    strncpy(post, json_string, length);

    //call ckvs_post with the latterly computed arguments
    err = ckvs_post(conn, url, post);
    free(post); post = NULL;
    if (err != ERR_NONE) {
        //error
        return err;
    }

    return ERR_NONE;
}

// ======================================================================
int ckvs_client_new(_unused const char *url, _unused int optargc, _unused char **optargv) {

    return NOT_IMPLEMENTED;
}

// ======================================================================
int ckvs_client_delete(_unused const char *url, _unused int optargc, _unused char **optargv) {

    return NOT_IMPLEMENTED;
}

