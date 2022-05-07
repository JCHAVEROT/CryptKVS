/**
 * @file ckvs_client.c
 * @brief c.f. ckvs_client.c
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

/**
 * @brief Performs the 'stats' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 0)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_stats(const char *url, int optargc, char **optargv) {
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

    //initialiaze the struct ckvs
    struct CKVS* ckvs = NULL;

    //initialize the connection and check errors
    int err = ckvs_rpc_init(&conn, (const char*) url);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    err = ckvs_rpc(&conn, "stats");
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //trivial test from etape 3
    pps_printf("\n\n%s\n\n", conn.resp_buf);

    struct json_object* root_obj = json_tokener_parse(conn.resp_buf);
    if (root_obj == NULL) {
        //error
        pps_printf("%s\n", "An error occured when parsing the string into a json object");
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }

    err = retrieve_ckvs_from_json(ckvs, root_obj);
    if (err != ERR_NONE) {
        //error
        pps_printf("%s\n", "vnfefefvnvnvn");
        ckvs_rpc_close(&conn);
        json_object_put(root_obj);
        return err;
    }

    //print the content downloaded from the server
    print_header(&(ckvs->header));

    //print the key of the entries
    for (size_t i = 0; i < ckvs->header.table_size; ++i) {
        if (strlen(ckvs->entries[i].key) != 0) {
            print_entry(&(ckvs->entries[i]));
        }
    }

    //free the struct JSON
    err = json_object_put(root_obj);
    if (err != 1) {
        //error
        ckvs_rpc_close(&conn);
        return err;
    }

    //close the connection
    ckvs_rpc_close(&conn);

    //free pointers
    //free(ckvs->entries);

    return ERR_NONE;
}

int retrieve_ckvs_from_json(struct CKVS* ckvs, const struct json_object* obj) {

    //check pointers
    if (ckvs == NULL || obj == NULL) {
        //error
        pps_printf("%s\n", "gleubeusteufeu");
        return ERR_INVALID_ARGUMENT;
    }

    int err = retrieve_ckvs_header_from_json(ckvs, obj);
    if (err != ERR_NONE) {
        //error
        pps_printf("%s\n", "papapap");
        return err;
    }

    struct json_object* keys_json_object = NULL;
    if (!json_object_object_get_ex(obj, "keys", &keys_json_object)) {
        pps_printf("%s\n", "An error occured : did not find the json array keys");
        return ERR_IO;
    }

    //pps_printf("\n%d\n", ckvs->header.table_size);
    ckvs->entries = calloc(ckvs->header.table_size, sizeof(ckvs_entry_t));
    for (size_t i = 0; i < json_object_array_length(keys_json_object); ++i) {
        struct json_object* temp_obj = json_object_array_get_idx(keys_json_object, i);
        if (temp_obj == NULL) {
            //error
            pps_printf("%s\n", "Adzdzdzd");
            free(ckvs->entries);
            return ERR_IO;
        }
        strncpy(ckvs->entries[i].key, json_object_get_string(temp_obj), CKVS_MAXKEYLEN);
    }

    return ERR_NONE;

}

int get_string(const struct json_object* obj, const char* key, char* buf) {
    //check pointers
    if (obj == NULL || key == NULL || buf == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //get the right json object
    struct json_object* value = NULL;
    if (!json_object_object_get_ex(obj, key, &value)) {
        pps_printf("%s %s\n", "An error occured : did not find the key", key);
        return ERR_IO;
    }

    //get the string from the json object
    const char* string_from_obj = json_object_get_string(value);
    if (string_from_obj == NULL) {
        //error
        pps_printf("%s", "bouououou");
        return ERR_IO;
    }

    //copy in the buffer
    strcpy(buf, string_from_obj);

    return ERR_NONE;
}

int get_int(const struct json_object* obj, const char* key, int* buf) {
    //check pointers
    if (obj == NULL || key == NULL || buf == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    struct json_object* value = NULL;
    if (!json_object_object_get_ex(obj, key, &value)) {
        pps_printf("%s %s", "An error occured : did not find the key", key);
        return ERR_IO;
    }

    //assign to the buffer the value found
    *buf = json_object_get_int(value);

    return ERR_NONE;
}



int retrieve_ckvs_header_from_json(struct CKVS* ckvs, const struct json_object* obj) {
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
        pps_printf("%s\n", "azafafafa");
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
        pps_printf("%s\n", "tetetete");
        return err;
    }
    //check that it is the good version, i.e. 1
    if (infos[0] != 1) {
        //error
        return ERR_CORRUPT_STORE;
    }

    err = get_int(obj, "table_size", (int *) &infos[1]);
    if (err != ERR_NONE) {
        //error
        pps_printf("%s\n", "pevpevppv");
        return err;
    }
    //check that the table has a size power of 2
    uint32_t table_size = infos[1];
    while (table_size >= 2) {
        if (table_size % 2 != 0) break;
        table_size = table_size / 2;
    }
    if (table_size != 1) {
        //error
        return ERR_CORRUPT_STORE;
    }

    err = get_int(obj, "threshold_entries", &infos[2]);
    if (err != ERR_NONE) {
        //error
        pps_printf("%s\n", "dzdzdzdzdzdzdzd");
        return err;
    }

    err = get_int(obj, "num_entries", &infos[3]);
    if (err != ERR_NONE) {
        //error
        pps_printf("%s\n", "mammamam");
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
/*
void ckvs_close(struct CKVS *ckvs) {
    //check if the argument is valid, if so exit the function without doing anything
    if (ckvs == NULL) {
        //error
        return;
    }
    //close to file of the CKVS and make it point to NULL
    if (ckvs->entries != NULL) {
        free(ckvs->entries);
    }
    ckvs->entries = NULL;
}
*/
/**
 * @brief Performs the 'get' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 2)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_get(const char *url, int optargc, char **optargv);

/* *************************************************** *
 * TODO WEEK 13                                        *
 * *************************************************** */
int ckvs_client_set(const char *url, int optargc, char **optargv);

int ckvs_client_new(const char *url, int optargc, char **optargv);
