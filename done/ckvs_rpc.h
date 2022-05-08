/**
 * @file ckvs_rpc.h
 * @brief client-side RPC using CURL
 * @author E Bugnion
 */

#pragma once
#include <curl/curl.h>
#include "ckvs_io.h"


/**
 * @brief maximal size of the encrypted value.  hex-encoded is 2x
 */
#define CKVS_MAX_VALUE_LEN_HTTP_QUERY (14*32)

struct json_object;

/**
 * @brief Holds the client state that represents a connection to a remote CKVS server
 */
typedef struct ckvs_connection {
    CURL *curl;         /**< CURL instance used for the connection */
    const char *url;    /**< url to the remote server */
    char *resp_buf;     /**< buffer that will hold the response of the server */
    size_t resp_size;   /**< size of resp_buf */
} ckvs_connection_t;


/**
 * @brief Initializes connection to the remote server at url.
 * @param conn (struct ckvs_connection*) the connection to initialize
 * @param url (const char*) target URL (string is not copied)
 * @return int, error code
 */
int ckvs_rpc_init(struct ckvs_connection *conn, const char *url);

/**
 * @brief Cleans up connection to remote server.
 * @param conn (struct ckvs_connection*) the connection to cleanup
 */
void ckvs_rpc_close(struct ckvs_connection *conn);


/* *************************************************** *
 * TODO WEEK 11                                        *
 * *************************************************** */
/**
 * @brief Sends an HTTP GET request to the connected server,
 * using the url and GET payload.
 *
 * @param conn (struct ckvs_connection*) the connection to the server
 * @param GET (const char*) the GET payload
 * @return int, error code
 */
int ckvs_rpc(struct ckvs_connection *conn, const char *GET);


/* *************************************************** *
 * TODO WEEK 13                                        *
 * *************************************************** */

/**
 * @brief Retrives the ckvs from a json object.
 *
 * @param ckvs (struct ckvs*) the ckvs in which we put the read content
 * @param obj (const json_object*) the json object we retrieve the information from
 * @return int, error code
 */
int retrieve_ckvs_from_json(struct CKVS* ckvs, const struct json_object* obj);


/**
 *
 * @param ckvs
 * @param obj
 * @return
 */
int retrieve_ckvs_header_from_json(struct CKVS *ckvs, const struct json_object *obj);

/**
 * @brief Sends an HTTP POST request to the connected server,
 * using its url, and the GET and POST payloads.
 *
 * @param conn (struct ckvs_connection*) the connection to the server
 * @param GET (const char*) the GET payload. Should already contain the fields "name" and "offset".
 * @param POST (const char*) the POST payload
 * @return int, error code
 */
int ckvs_post(struct ckvs_connection* conn, const char* GET, const char* POST);


/**
 *
 * @param obj
 * @param key
 * @param buf
 * @return
 */
int get_string(const struct json_object* obj, const char* key, char* buf);

/**
 *
 * @param obj
 * @param key
 * @param buf
 * @return
 */
int get_int(const struct json_object* obj, const char* key, int* buf);


