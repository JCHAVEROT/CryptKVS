/**
 * @file ckvs_client.h
 * @brief client-side operations over network
 * @author E Bugnion, A. Clergeot
 */
#pragma once


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
 * @brief Retrives the ckvs from a json object.
 *
 * @param ckvs (struct ckvs*) the ckvs in which we put the read content
 * @param obj (const json_object*) the json object we retrieve the information from
 * @return int, error code
 */
int retrieve_ckvs_from_json(struct ckvs* ckvs, const struct json_object* obj);

int retrieve_ckvs_header_from_json(struct ckvs* ckvs, const struct json_object* obj);

int get_string(const struct json_object* obj, const char* key, char* buf);

int get_int(const struct json_object* obj, const char* key, int* buf);

//void ckvs_close(struct CKVS *ckvs);



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
