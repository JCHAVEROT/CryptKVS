/**
 * @file ckvs_rpc.c
 * @brief RPC handling using libcurl
 * @author E. Bugnion
 *
 * Includes example from https://curl.se/libcurl/c/getinmemory.html
 */
#include <stdlib.h>
#include <json-c/json.h>
#include "ckvs_rpc.h"
#include "error.h"
#include "util.h"
#include "ckvs_utils.h"
#include "ckvs_io.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "ckvs.h"


/**
 * ckvs_curl_WriteMemoryCallback -- lifted from https://curl.se/libcurl/c/getinmemory.html
 *
 * @brief Callback that gets called when CURL receives a message.
 * It writes the payload inside ckvs_connection.resp_buf.
 * Note that it is already setup in ckvs_rpc_init.
 *
 * @param contents (void*) content received by CURL
 * @param size (size_t) size of an element of of content. Always 1
 * @param nmemb (size_t) number of elements in content
 * @param userp (void*) points to a ckvs_connection (set with the CURLOPT_WRITEDATA option)
 * @return (size_t) the number of written bytes, or 0 if an error occured
 */
static size_t ckvs_curl_WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct ckvs_connection *conn = (struct ckvs_connection *)userp;

    char *ptr = realloc(conn->resp_buf, conn->resp_size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        debug_printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    conn->resp_buf = ptr;
    memcpy(&(conn->resp_buf[conn->resp_size]), contents, realsize);
    conn->resp_size += realsize;
    conn->resp_buf[conn->resp_size] = 0;

    return realsize;
}


int ckvs_rpc_init(struct ckvs_connection *conn, const char *url)
{
    if (conn==NULL||url==NULL){
        return ERR_INVALID_ARGUMENT;
    }
    bzero(conn, sizeof(*conn));

    conn->url  = url;
    conn->curl = curl_easy_init();
    if (conn->curl == NULL) {
        return ERR_OUT_OF_MEMORY;
    }
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ckvs_curl_WriteMemoryCallback);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *)conn);

    return ERR_NONE;
}

void ckvs_rpc_close(struct ckvs_connection *conn)
{
    if (conn == NULL)
        return;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
    }
    if (conn->resp_buf) {
        free(conn->resp_buf);
    }
    bzero(conn, sizeof(*conn));
}

int ckvs_rpc(struct ckvs_connection *conn, const char *GET){
    //check pointers
    if (conn==NULL||GET==NULL){
        return ERR_INVALID_ARGUMENT;
    }

    //specify the URL
     char *url = calloc(strlen(conn->url)+ strlen(GET) + 2, sizeof(char));
    if (url == NULL) {
        return ERR_OUT_OF_MEMORY;
    }
    strncpy(url, conn->url, strlen(conn->url));
    strcat(url, "/");
    strcat(url, GET);

    //pps_printf("%s \n",url);


    CURLcode ret = curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    free(url);
    if (ret != CURLE_OK) {
        //error
        return ERR_OUT_OF_MEMORY;
    }

    ret = curl_easy_perform(conn->curl);
    if (ret != CURLE_OK) {
        //error

        return ERR_TIMEOUT;
    }

    return ERR_NONE;

}

int get_string(const struct json_object *obj, const char *key, char *buf) {
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

int get_int(const struct json_object *obj, const char *key, int *buf) {
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
        pps_printf("%s\n", "An error occured : did not find the json array keys");
        return ERR_IO;
    }

    //pps_printf("\n%d\n", ckvs->header.table_size);
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






