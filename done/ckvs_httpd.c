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

// ======================================================================
/**
 * @brief To add an inner json object associated to the key with value the given string.
 *
 * @param obj (struct json_object*) the parent json object
 * @param key (const char*) the key associated to the string we add
 * @param val (char*) the string we add to the json object
 * @return int, error code
 */
static int add_string(struct json_object *obj, const char *key, const char *val) {
    //check pointers
    if (obj == NULL || key == NULL || val == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    return json_object_object_add(obj, key, json_object_new_string(val));
}

// ======================================================================
/*
static int add_array(const struct json_object *obj, const char *key, const char *array[], size_t size) {
    //check pointers
    if (obj == NULL || key == NULL || array == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    struct json_object *arr = json_object_new_array();

    for (size_t i = 0; i < size; i++) {
        json_object_array_add(arr, json_object_new_string(array[i]));
        pps_printf("%s", array[i]);
    }

    return json_object_object_add((struct json_object *) obj, key, arr);
}
*/

// ======================================================================
/**
 * @brief To add an inner json object associated to the key with value the given integer.
 *
 * @param obj (struct json_object*) the parent json object
 * @param key (const char*) the key associated to the integer we add
 * @param val (int) the integer we add to the json object
 * @return int, error code
 */
static int add_int(struct json_object *obj, const char *key, int val) {
    //check pointers
    if (obj == NULL || key == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    return json_object_object_add(obj, key, json_object_new_int(val));
}

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
        return;
        ckvs_close(ckvs);
    }

    if (ckvs == NULL || hm == NULL) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    //create the new json object
    json_object *object = json_object_new_object();

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
        mg_error_msg(nc, ERR_IO);
        return;
    }

    //close the ckvs
    ckvs_close(ckvs);

    mg_error_msg(nc, ERR_NONE);
}

// ======================================================================
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
    int err = mg_http_get_var(&hm->query, "auth_key", auth_key_buffer, 1024);
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
    json_object *object = json_object_new_object();

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

    //close the ckvs
    ckvs_close(ckvs);

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
            // TODO: handle commands calls
            if (mg_http_match_uri(hm, "/stats")) {
                handle_stats_call(nc, ckvs, hm);
            } else if (mg_http_match_uri(hm, "/get")) {
                handle_get_call(nc, ckvs, hm);
            } else {
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


