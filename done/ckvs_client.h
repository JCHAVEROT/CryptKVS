/**
 * @file ckvs_client.h
 * @brief client-side operations over network
 * @author E Bugnion, A. Clergeot
 */
#pragma once
#include <json-c/json.h>

#include "ckvs_crypto.h"

/* *************************************************** *
 * TODO WEEK 10                                        *
 * *************************************************** */
/**
 * @brief Performs the 'stats' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 0)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_stats(const char *url, int optargc, char **optargv);

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
/**
 * @brief Performs the 'set' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 3)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_set(const char *url, int optargc, char **optargv);

/**
 * @brief Performs the 'new' command by connecting to the remote server at url.
 *
 * @param url (const char*) the url of the remote CKVS server
 * @param optargc (int) the number of optional arguments that are provided (should be 2)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_client_new(const char *url, int optargc, char **optargv);

/**
 * @brief Retrives the ckvs from a json object.
 *
 * @param ckvs (struct ckvs*) the ckvs in which we put the read content
 * @param obj (const json_object*) the json object we retrieve the information from
 * @return int, error code
 */
int retrieve_ckvs_from_json(struct CKVS* ckvs, const struct json_object* obj);

/**
 * @brief Retrives the ckvs header from a json object.
 *
 * @param ckvs (struct ckvs*) the ckvs in which we put the read content for the header
 * @param obj (const json_object*) the json object we retrieve the information from
 * @return int, error code
 */
int retrieve_ckvs_header_from_json(struct CKVS *ckvs, const struct json_object *obj);

/**
 * @brief Common part of ckvs_client_get and ckvs_client_set. If set_value is NULL then get is done otherwise set is done.
 *
 * @param url (const char*) the url of the server of interest
 * @param key (const char*) the key of the entry to set
 * @param pwd (const char*) the password of the entry to set
 * @param set_value (const char*) the not yet encrypted new value for set (NULL for get).
 * @return int, an error code
 */
int ckvs_client_getset(const char *url, const char *key, const char *pwd, const char *set_value);

/**
 * @brief Do the get part of the client getset function.
 *
 * @param conn (struct ckvs_connection*) the connection to the server
 * @param ckvs_mem (struct ckvs_memrecord) holds the variables necessary to compute a master key
 * @param url (const char *) the ready url of the server with the arguments
 * @return int, an error code
 */
int do_client_get(struct ckvs_connection *conn, ckvs_memrecord_t *ckvs_mem, char *url);

/**
 * @brief Do the set part of the client getset function.
 *
 * @param conn (struct ckvs_connection*) the connection to the server
 * @param ckvs_mem (struct ckvs_memrecord) holds the variables necessary to compute a master key
 * @param url (const char *) the not yet ready url of the server with the arguments
 * @param set_value (const char*) the not yet encrypted new value for set
 * @return int, an error code
 */
int do_client_set(struct ckvs_connection *conn, ckvs_memrecord_t *ckvs_mem, char *url, const char *set_value);


