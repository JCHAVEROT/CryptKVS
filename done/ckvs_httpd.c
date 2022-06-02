/**
 * @file ckvs_httpd.c
 * @brief webserver
 *
 * @author Edouard Bugnion
 */

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "ckvs_httpd.h"
#include <assert.h>
#include "libmongoose/mongoose.h"
#include <json-c/json.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include "util.h"


// Handle interrupts, like Ctrl-C
static int s_signo;

#define HTTP_ERROR_CODE 500
#define HTTP_OK_CODE 200
#define HTTP_FOUND_CODE 302
#define HTTP_NOTFOUND_CODE 404
#define BUFFER_SIZE 1024
#define NAME_SIZE 100

// ======================================================================
static char *get_urldecoded_argument(struct mg_http_message *hm, const char *arg) {
    //check pointers
    if (hm == NULL || arg == NULL) {
        //error
        return NULL;
    }

    //retrieve the the argument called arg from hm
    char *buf = calloc(CKVS_MAXKEYLEN + 1, sizeof(char));
    int err = mg_http_get_var(&hm->query, arg, buf, BUFFER_SIZE);
    if (err < 1) {
        //error
        free(buf); buf = NULL;
        return NULL;
    }

    //initialize the curl
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        //error
        free(buf); buf = NULL;
        return NULL;
    }

    //get the unescaped version of the argument
    int size = CKVS_MAXKEYLEN;
    char *result = curl_easy_unescape(curl, buf, CKVS_MAXKEYLEN + 1, &size);

    //free objects
    curl_easy_cleanup(curl);
    free(buf); buf = NULL;

    return result;
}

// ======================================================================
/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection *nc, int err) {
    assert(err >= 0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

// ======================================================================
/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo) {
    s_signo = signo;
}

// ======================================================================
static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm) {
    //check pointers
    if (nc == NULL) {
        //error
        ckvs_close(ckvs);
        return;
    }

    if (ckvs == NULL || hm == NULL) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    //create the new json object
    struct json_object *object = json_object_new_object();

    //add the header string of ckvs
    int err = add_string(object, "header_string", ckvs->header.header_string);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //add the version of ckvs
    err = add_int(object, "version", (int) ckvs->header.version);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //add the table size of ckvs
    err = add_int(object, "table_size", (int) ckvs->header.table_size);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //add the threshold entries of ckvs
    err = add_int(object, "threshold_entries", (int) ckvs->header.threshold_entries);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //add the number of entries of ckvs
    err = add_int(object, "num_entries", (int) ckvs->header.num_entries);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //create the array to store the keys of ckvs
    json_object *array = json_object_new_array();
    for (size_t i = 0; i < ckvs->header.table_size; ++i) {
        char key[CKVS_MAXKEYLEN + 1] = {0};
        strncpy(key, ckvs->entries[i].key, 32);

        if (strcmp(key, "\0") != 0) { //verify the key is not empty
            json_object_array_add(array, json_object_new_string(key));
        }
    }

    //add the array to the json object
    err = json_object_object_add(object, "keys", array);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //serialize the json onject
    size_t length = 0;
    const char *json_string = json_object_to_json_string_length(object, JSON_C_TO_STRING_PRETTY, &length);

    //submit the response
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", json_string);

    //free the json object
    err = json_object_put(object);
    if (err != 1) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //close the ckvs
    ckvs_close(ckvs);

    mg_error_msg(nc, ERR_NONE);
}

// ======================================================================
/**
 * @brief Handler for a set call.
 *
 * @param nc the http connection
 * @param ckvs the ckvs table
 * @param hm the http message
 */
static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm) {
    //check pointers
    if (nc == NULL) {
        //error
        ckvs_close(ckvs);
        return;
    }

    if (ckvs == NULL || hm == NULL) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    if (hm->body.len > 0) {
        int err = mg_http_upload(nc, hm, "/tmp");
        if (err < 0) {
            //error
            ckvs_close(ckvs);
            mg_error_msg(nc, ERR_IO);
            return;
        }
        return;
    }

    //TODO modulariser HANDLE get/set

    //get the url escaped key
    char *key = get_urldecoded_argument(hm, "key");
    if (key == NULL) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    //get the encoded auth key
    char *auth_key_buffer = calloc(SHA256_PRINTED_STRLEN, sizeof(char));
    if (auth_key_buffer == NULL) {
        //error
        curl_free(key);
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //retrieve the auth key and convert it in SHA256
    int err = mg_http_get_var(&hm->query, "auth_key", auth_key_buffer, BUFFER_SIZE);
    if (err < 1) {
        //error
        curl_free(key);
        ckvs_close(ckvs);
        free(auth_key_buffer); auth_key_buffer = NULL;
        mg_error_msg(nc, ERR_IO);
        return;
    }
    //initialize the ckvs_sha for the auth key
    ckvs_sha_t auth_key;
    memset(&auth_key, 0, sizeof(ckvs_sha_t));

    //hex-decode the string of the auth key into SHA256
    SHA256_from_string(auth_key_buffer, &auth_key);
    free(auth_key_buffer); auth_key_buffer = NULL;

    //initialize a pointer on a ckvs_entry to store the entry to be found
    ckvs_entry_t *ckvs_out;
    memset(&ckvs_out, 0, sizeof(ckvs_entry_t *));

    //with the newly computed key and auth key, find the right entry in the table
    err = ckvs_find_entry(ckvs, key, &auth_key, &ckvs_out);
    curl_free(key);
    if (err != ERR_NONE) {
        //error
        if (err != ERR_KEY_NOT_FOUND && err != ERR_DUPLICATE_ID) {
            //so not to close the table if the key was not found or password was incorrect
            ckvs_close(ckvs);
        }
        mg_error_msg(nc, err);
        return;
    }

    //get the file name
    char *name = calloc(NAME_SIZE, sizeof(char));
    err = mg_http_get_var(&hm->query, "name", name, BUFFER_SIZE);
    if (err < 1) {
        //error
        ckvs_close(ckvs);
        free(name); name = NULL;
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //compute the path
    char* path = calloc(5 + strlen(name) + 1, sizeof(char));
    if (path == NULL) {
        //error
        ckvs_close(ckvs);
        curl_free(key);
        mg_error_msg(nc, ERR_OUT_OF_MEMORY);
        return;
    }
    strcat(path, "/tmp/");
    strcat(path, name);
    free(name); name = NULL;

    //initialize buffer and its size
    char *buffer = NULL; size_t buffer_size = 0;

    //read file called filename and prints it in the buffer and check errors
    err = read_value_file_content(path, &buffer, &buffer_size);
    free(path); path = NULL;
    if (err != ERR_NONE) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, err);
        return;
    }

    //retrieve the json object
    struct json_object *root_obj = json_tokener_parse(buffer);
    free(buffer); buffer = NULL; buffer_size = 0;
    if (root_obj == NULL) {
        //error, need to get which one
        ckvs_close(ckvs);
        json_object_put(root_obj);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //get the hex-encoded c2 string, decode it into SHA256 and put its value in the table
    char c2_hex[SHA256_PRINTED_STRLEN];
    err = get_string(root_obj, "c2", c2_hex);
    if (err != ERR_NONE) {
        //error
        ckvs_close(ckvs);
        json_object_put(root_obj);
        mg_error_msg(nc, err);
        return;
    }
    struct ckvs_sha c2;
    memset(&c2, 0, sizeof(ckvs_sha_t));
    SHA256_from_string(c2_hex, &c2);
    ckvs_out->c2 = c2;

    //get the hex-encoded data
    struct json_object *data_json_obj = NULL;
    if (!json_object_object_get_ex(root_obj, "data", &data_json_obj)) {
        //error
        ckvs_close(ckvs);
        json_object_put(root_obj);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //get the string from the json object
    const char *data_hex = json_object_get_string(data_json_obj);
    if (data_hex == NULL) {
        //error
        ckvs_close(ckvs);
        json_object_put(root_obj);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    unsigned char *data = calloc(strlen(data_hex) / 2 + 1, sizeof(char));
    if (data == NULL) {
        //error
        ckvs_close(ckvs);
        json_object_put(root_obj);
        mg_error_msg(nc, ERR_OUT_OF_MEMORY);
        return;
    }

    int decoded_size = hex_decode(data_hex, data);
    if (decoded_size == -1) {
        //error
        ckvs_close(ckvs);
        free(data); data=NULL;
        json_object_put(root_obj);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //write the new entry
    err = ckvs_write_encrypted_value(ckvs, ckvs_out, data, (uint64_t) decoded_size);
    json_object_put(root_obj);
    free(data); data=NULL;
    if (err != ERR_NONE) {
        //error
        mg_error_msg(nc, err);
        return;
    }

    //tell the client everything went well
    mg_http_reply(nc, HTTP_OK_CODE, "", "");
    mg_error_msg(nc, ERR_NONE);
}

// ======================================================================
/**
 * @brief Handler for a get call.
 *
 * @param nc the http connection
 * @param ckvs the ckvs table
 * @param hm the http message
 */
static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm) {
    //check pointers
    if (nc == NULL) {
        //error
        ckvs_close(ckvs);
        return;
    }

    if (ckvs == NULL || hm == NULL) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    //get the url escaped key
    char *key = get_urldecoded_argument(hm, "key");
    if (key == NULL) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    //get the encoded auth key
    char *auth_key_buffer = calloc(SHA256_PRINTED_STRLEN, sizeof(char));
    if (auth_key_buffer == NULL) {
        //error
        curl_free(key);
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //retrieve the auth key and convert it in SHA256
    int err = mg_http_get_var(&hm->query, "auth_key", auth_key_buffer, BUFFER_SIZE);
    if (err < 1) {
        //error
        curl_free(key);
        ckvs_close(ckvs);
        free(auth_key_buffer); auth_key_buffer = NULL;
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //initialize the ckvs_sha for the auth key
    ckvs_sha_t auth_key;
    memset(&auth_key, 0, sizeof(ckvs_sha_t));

    //hex-decode the string of the auth key into SHA256
    SHA256_from_string(auth_key_buffer, &auth_key);
    free(auth_key_buffer); auth_key_buffer = NULL;

    //initialize a pointer on a ckvs_entry to store the entry to be found
    ckvs_entry_t *ckvs_out;
    memset(&ckvs_out, 0, sizeof(ckvs_entry_t *));

    //with the newly computed key and auth key, find the right entry in the table
    err = ckvs_find_entry(ckvs, key, &auth_key, &ckvs_out);
    if (err != ERR_NONE) {
        //error
        curl_free(key);
        ckvs_close(ckvs);
        mg_error_msg(nc, err);
        return;
    }

    //free pointers
    curl_free(key);

    if (ckvs_out->value_len == 0) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_NO_VALUE);
        return;
    }

    //initialize the json_object that will contain c2 and the data
    struct json_object *object = json_object_new_object();

    //initialize the hex-encoded string that will contain the SHA256 of c2
    char c2[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&ckvs_out->c2, c2);

    err = add_string(object, "c2", c2);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        ckvs_close(ckvs);
        return;
    }

    //place the pointer in the right position in the file, corresponding to the beginnning of the data
    err = fseek(ckvs->file, (long int) ckvs_out->value_off, SEEK_SET);
    if (err != ERR_NONE) {
        //error
        ckvs_close(ckvs);
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //initialize the string where the encrypted secret will be stored
    unsigned char *encrypted = calloc(ckvs_out->value_len, sizeof(unsigned char));
    if (encrypted == NULL) {
        //error
        json_object_put(object);
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_OUT_OF_MEMORY);
        return;
    }

    //read the encrypted secret
    size_t nb_ok = fread(encrypted, sizeof(unsigned char), ckvs_out->value_len, ckvs->file);
    if (nb_ok != ckvs_out->value_len) {
        //error
        json_object_put(object);
        ckvs_close(ckvs);
        free(encrypted); encrypted = NULL;
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //initialize the buffer for the hex-encoded and encoded data
    char *data = calloc(ckvs_out->value_len * 2 + 1, sizeof(unsigned char));
    if (data == NULL) {
        //error
        json_object_put(object);
        ckvs_close(ckvs);
        free(encrypted); encrypted = NULL;
        mg_error_msg(nc, ERR_OUT_OF_MEMORY);
        return;
    }

    //hex-encode the encrypted data
    hex_encode(encrypted, ckvs_out->value_len, data);
    free(encrypted); encrypted = NULL;

    //add the hex-encoded encrypted data in the json object
    err = add_string(object, "data", data);
    free(data); data = NULL;
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        ckvs_close(ckvs);
        return;
    }

    //serialize the json onject
    size_t length = 0;
    const char *json_string = json_object_to_json_string_length(object, JSON_C_TO_STRING_PRETTY, &length);

    //submit the response
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", json_string);

    //free the json object
    err = json_object_put(object);
    if (err != 1) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_IO);
        return;
    }

    mg_error_msg(nc, ERR_NONE);
}

// ======================================================================
/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(struct mg_connection *nc, int ev, void *ev_data, void *fn_data) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS *) fn_data;

    if (ev != MG_EV_POLL)
        debug_printf("Event received %d", ev);

    switch (ev) {
        case MG_EV_POLL:
        case MG_EV_CLOSE:
        case MG_EV_READ:
        case MG_EV_WRITE:
        case MG_EV_HTTP_CHUNK:
            break;

        case MG_EV_ERROR:
            debug_printf("httpd mongoose error \n");
            break;
        case MG_EV_ACCEPT:
            // students: no need to implement SSL
            assert(ckvs->listening_addr);
            debug_printf("accepting connection at %s\n", ckvs->listening_addr);
            assert(mg_url_is_ssl(ckvs->listening_addr) == 0);
            break;

        case MG_EV_HTTP_MSG:
            //handle commands calls
            if (mg_http_match_uri(hm, "/stats")) {
                handle_stats_call(nc, ckvs, hm);
            } else if (mg_http_match_uri(hm, "/get")) {
                handle_get_call(nc, ckvs, hm);
            } else if (mg_http_match_uri(hm, "/set")) {
                handle_set_call(nc, ckvs, hm);
            }else {
                mg_error_msg(nc, NOT_IMPLEMENTED);
            }

            break;

        default:
            fprintf(stderr, "ckvs_event_handler %u\n", ev);
            assert(0);
    }
}

// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv) {
    if (optargc < 1)
        return ERR_NOT_ENOUGH_ARGUMENTS;
    else if (optargc > 1)
        return ERR_TOO_MANY_ARGUMENTS;

    /* Create server */

    signal(SIGINT, signal_handler); //adds interruption signals to the signal handler
    signal(SIGTERM, signal_handler);

    struct CKVS ckvs;
    int err = ckvs_open(filename, &ckvs);

    if (err != ERR_NONE) {
        return err;
    }

    ckvs.listening_addr = optargv[0];

    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr);

    c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
    if (c == NULL) {
        debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    debug_printf("Starting CKVS server on %s for database %s\n", ckvs.listening_addr, filename);

    while (s_signo == 0) {
        mg_mgr_poll(&mgr, 1000); //infinite loop as long as no termination signal occurs
    }
    mg_mgr_free(&mgr);
    ckvs_close(&ckvs);
    debug_printf("Exiting HTTPD server\n");
    return ERR_NONE;
}

