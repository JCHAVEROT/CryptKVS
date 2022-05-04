/**
 * @file ckvs_local.h
 * @brief ckvs_local -- operations on local databases
 *
 * @author E. Bugnion
 */

#pragma once

#include "ckvs_utils.h"
#include "ckvs.h"
#include "ckvs_crypto.h"
#include "ckvs_io.h"


/* *************************************************** *
 * TODO WEEK 04                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 * DO NOT FORGET TO USE pps_printf to print the header/entries!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments (should be 0)
 * @param optargv (char*) the arguments (not used)
 * @return int, an error code
 */
int ckvs_local_stats(const char* filename, int optargc, char* optargv[]);

/* *************************************************** *
 * TODO WEEK 05                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'get' command,
 * ie. fetches, decrypts and prints the entry corresponding to the key and password.
 * DO NOT FORGET TO USE pps_printf to print to value!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments (should be 2)
 * @param optargv (char*) the arguments : should contain the key and the password of the entry to get
 * @return int, an error code
 */
int ckvs_local_get(const char* filename, int optargc, char* optargv[]);

/* *************************************************** *
 * TODO WEEK 06                                        *
 * *************************************************** */

/**
 * @brief Common part of ckvs_local_get and ckvs_local_set. If set_value is NULL then get is done otherwise set is done
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param key (const char*) the key of the entry to set
 * @param pwd (const char*) the password of the entry to set
 * @param set_value (const char*) the path to the file which contains what will become the new encrypted content of the entry(only for ckvs_local_set).
 * @return int, an error code
 */
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char *set_value);


/**
 * @brief Auxiliary function to easily free set_value_encrypted's dynamic allocation
 *
 * @param sve (const char*)
 * @param sve_length size_t
 * @return void
 */
void free_sve(unsigned char **sve, size_t *sve_length);

/**
 * @brief Auxiliary function to easily free an unsigned char*
 *
 * @param a
 */
void free_uc(unsigned char** a);

/**
 * @brief do the set part of the getset function
 *
 * @param ckvs
 * @param ckvs_out
 * @param ckvs_mem
 * @return
 */
int do_get( CKVS_t* ckvs,ckvs_entry_t* ckvs_out,ckvs_memrecord_t * ckvs_mem);

/**
 *
 * @param ckvs
 * @param ckvs_out
 * @param ckvs_mem
 * @param set_value
 * @return
 */
int do_set(CKVS_t* ckvs,ckvs_entry_t* ckvs_out,ckvs_memrecord_t * ckvs_mem,const char *set_value);





/**
 * @brief Opens the CKVS database at the given filename and executes the 'set' command,
 * ie. fetches the entry corresponding to the key and password and
 * then sets the encrypted content of valuefilename as new content.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments (should be 3)
 * @param optargv (char*) the arguments : should contain the key and the password of the entry to set,
 *                                        and the path to the file which contains what will become the new encrypted content of the entry
 * @return int, an error code
 */
int ckvs_local_set(const char* filename, int optargc, char* optargv[]);


/* *************************************************** *
 * TODO WEEK 07                                        *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at the given filename and executes the 'new' command,
 * ie. creates a new entry with the given key and password.
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param optargc (int) number of arguments (should be 2)
 * @param optargv (char*) the arguments : should contain the key and the password of the entry to create
 * @return int, an error code
 */
int ckvs_local_new(const char* filename, int optargc, char* optargv[]);

/* *************************************************** *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */

