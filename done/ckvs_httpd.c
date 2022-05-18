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

static int add_string(const struct json_object *obj, const char *key, char *val) {
    return json_object_object_add(obj, key, json_object_new_string(val));
}

static int add_array(const struct json_object *obj, const char *key, char* array[],size_t size) {

    struct json_object*  arr=  json_object_new_array();

    for(size_t i=0;i<size;i++){
        json_object_array_add(arr, json_object_new_string(array[i]));
        pps_printf("%s",array[i]);
    }

    return json_object_object_add(obj, key, arr);
}

static int add_int(const struct json_object *obj, const char *key, char *val) {
    return json_object_object_add(obj, key, json_object_new_int(val));
}

static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg)
{
    //check pointers
    if (hm == NULL || arg == NULL) {
        //error
        return NULL;
    }

    //retrieve the the argument called arg from hm
    char* buf = calloc(CKVS_MAXKEYLEN+1, sizeof(char));
    int err = mg_http_get_var(&hm->query, arg, buf, BUFFER_SIZE);
    if (err < 1) {
        //error
        return NULL;
    }


    CURL* curl = curl_easy_init();
    if (curl == NULL) {
        //error
        return NULL;
    }
    //get the unescaped version of the argument
    int size = CKVS_MAXKEYLEN;
    char* result = curl_easy_unescape(curl, buf, CKVS_MAXKEYLEN+1, &size);
    curl_easy_cleanup(curl);
    free(buf); buf = NULL;
    return result;

}

/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection* nc, int err)
{
    assert(err>=0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo)
{
    s_signo = signo;
}

static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs,
                              _unused struct mg_http_message *hm)
{
    //check pointers
    if (nc == NULL) {
        //error
        return;
    }

    if (ckvs == NULL || hm == NULL) {
        //error
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;

    }

    //create the new json object
    json_object* object = json_object_new_object();
    //int err = json_object_put(object);


    //add the header string of ckvs
    int err = add_string(object, "header_string", ckvs->header.header_string);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        return;

    }

    //add the version of ckvs
    err = add_int(object, "version", ckvs->header.version);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        return;

    }

    //add the table size of ckvs
    err = add_int(object, "table_size", ckvs->header.table_size);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        return;

    }

    //add the threshold entries of ckvs
    err = add_int(object, "threshold_entries", ckvs->header.threshold_entries);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        return;

    }

    //add the number of entries of ckvs
    err = add_int(object, "num_entries", ckvs->header.num_entries);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        return;

    }


    //create the array to store the keys of ckvs
    json_object* array = json_object_new_array();
    for (size_t i = 0; i < ckvs->header.table_size; ++i) {
        const char key[33]={0};
             strncpy(&key, ckvs->entries[i].key,32);

        if (strcmp(key,"\0")!=0) { //verify the key is not empty
            json_object_array_add(array, json_object_new_string(key));
        }
    }

    //add the array to the json object
    err = json_object_object_add(object, "keys", array);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        return;

    }

    //serialize the json onject
    size_t length = 0;
    const char* json_string = json_object_to_json_string_length(object, JSON_C_TO_STRING_PRETTY, &length);



    //submit the response
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", json_string);

    //free the json object
    err = json_object_put(object);
    if (err != 1) {
        //error
        mg_error_msg(nc, ERR_IO);
        return;
    }
}

static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, struct mg_http_message *hm) {
    //check pointers
    if (nc == NULL) {
        //error
        return;
    }

    if (ckvs == NULL || hm == NULL) {
        //error
        mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        return;
    }

    //get the url escaped key
    char* key = get_urldecoded_argument(hm, "key");
    if (key == NULL) {
        mg_error_msg(nc, ERR_IO);
        return;

    }


    //get the encoded auth key
    char* auth_key_buffer = calloc(SHA256_PRINTED_STRLEN, sizeof(char));
    if (auth_key_buffer==NULL){
        curl_free(key);
        mg_error_msg(nc, ERR_IO);
        return;

    }

    int err = mg_http_get_var(&hm->query, "auth_key", auth_key_buffer, 1024);
    if (err < 1) {
        //error
        curl_free(key);
        free(auth_key_buffer); auth_key_buffer = NULL;
        mg_error_msg(nc, ERR_IO);
        return;

    }

    ckvs_sha_t auth_key={0};
    SHA256_from_string(auth_key_buffer,&auth_key);
    ckvs_entry_t* ckvs_out;
    memset(&ckvs_out,0, sizeof(ckvs_entry_t*));


    err = ckvs_find_entry(ckvs, key, &auth_key, &ckvs_out);

    if (err != ERR_NONE) {
        //error
        ckvs_close(ckvs);
        mg_error_msg(nc, err);
        return;
    }

    //free pointers
    curl_free(key);
    free(auth_key_buffer); auth_key_buffer = NULL;

    if (ckvs_out->value_len==0){
        ckvs_close(&ckvs);
        mg_error_msg(nc, ERR_NO_VALUE);
        return;
    }

    json_object* object = json_object_new_object();

    char c2[SHA256_PRINTED_STRLEN]={0};
    SHA256_to_string(&ckvs_out->c2,&c2);

    err = add_string(object, "c2", &c2);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        ckvs_close(ckvs);
        return;

    }

    err = fseek(ckvs->file,(long int) ckvs_out->value_off,SEEK_SET);
    if (err != ERR_NONE) {
        //error
        ckvs_close(ckvs);
        json_object_put(object);

        mg_error_msg(nc, ERR_IO);
        return ;
    }

    //initialize the string where the encrypted secret will be stored
    unsigned char *encrypted = calloc(ckvs_out->value_len, sizeof(unsigned char));
    if (encrypted == NULL) {
        json_object_put(object);
        mg_error_msg(nc, ERR_OUT_OF_MEMORY);
        return;
    }


    //read the encrypted secret
    size_t nb_ok = fread(encrypted, sizeof(unsigned char), ckvs_out->value_len, ckvs->file);
    if (nb_ok != ckvs_out->value_len) {
        //error
        json_object_put(object);
        ckvs_close(ckvs);
        free(encrypted);
        return ;
    }
     char *data  = calloc(ckvs_out->value_len*2+1, sizeof(unsigned char));
    if (data == NULL) {
        json_object_put(object);
        mg_error_msg(nc, ERR_OUT_OF_MEMORY);
        ckvs_close(ckvs);
        free(encrypted);
        return;
    }


    hex_encode(encrypted,ckvs_out->value_len,data);
    free(encrypted);
    encrypted=NULL;

    err = add_string(object, "data", data);
    free(data);
    if (err != ERR_NONE) {
        //error
        json_object_put(object);
        mg_error_msg(nc, ERR_IO);
        ckvs_close(ckvs);
        return;

    }

    //serialize the json onject
    size_t length = 0;
    const char* json_string = json_object_to_json_string_length(object, JSON_C_TO_STRING_PRETTY, &length);



    //submit the response
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", json_string);

    //free the json object
    err = json_object_put(object);
    if (err != 1) {
        //error
        mg_error_msg(nc, ERR_IO);
        return;
    }









}

// ======================================================================
/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(struct mg_connection *nc, int ev, void *ev_data, void *fn_data)
{
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS*) fn_data;

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
        assert (mg_url_is_ssl(ckvs->listening_addr) == 0);
        break;

    case MG_EV_HTTP_MSG:
        // TODO: handle commands calls
        if (mg_http_match_uri(hm,"/stats")) {
            handle_stats_call(nc, ckvs, hm);
        }
        else if (mg_http_match_uri(hm,"/get")) {
            handle_get_call(nc, ckvs, hm);
        } else {
            mg_error_msg(nc, ERR_INVALID_ARGUMENT);
        }

        break;

    default:
        fprintf(stderr, "ckvs_event_handler %u\n", ev);
        assert(0);
    }
}

// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv)
{
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
    if (c==NULL) {
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


