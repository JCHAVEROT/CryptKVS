/**
 * @file ckvs_io.h
 * @brief ckvs_io - IO operations for a local database
 * @author E Bugnion, A. Clergeot
 */
#pragma once

#include <stdint.h> // for uint64_t
#include <json-c/json.h>
#include "ckvs.h"
#include "ckvs_crypto.h"


/* *************************************************** *
 * TODO WEEK 04: Define struct CKVS here               *
 * *************************************************** */
/**
 * @brief Represents a CKVS database.
 */
struct CKVS {
    struct ckvs_header header;
    ckvs_entry_t *entries;
    FILE *file;
    const char* listening_addr;
};
typedef struct CKVS CKVS_t;

/* *************************************************** *
 * TODO WEEK 05: Open/close refactoring                *
 * *************************************************** */
/**
 * @brief Opens the CKVS database at filename.
 * Also checks that the database is valid, as described in 04.stats.md
 *
 * @param filename (const char*) the path to the database to open
 * @param ckvs (struct CKVS*) the struct that will be initialized
 * @return int, error code
 */
int ckvs_open(const char *filename, struct CKVS *ckvs);

/**
 * @brief helper function to read the header of ckvs
 *
 * @param ckvs (struct CKVS*) the struct that will be initialized
 * @return int, error code
 */
int read_header(CKVS_t *ckvs);

/**
 * @brief Closes the CKVS database and releases its resources.
 *
 * @param ckvs (struct CKVS*) the ckvs database to close
 */
void ckvs_close(struct CKVS *ckvs);

/* *************************************************** *
 * TODO WEEK 05                                        *
 * *************************************************** */
/**
 * @brief Finds the entry with the given (key, auth_key) pair in the ckvs database.
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param key (const char*) the key of the entry
 * @param auth_key (const struct ckvs_sha*) the auth_key of the entry
 * @param e_out (struct ckvs_entry**) points to a pointer to an entry. Used to store the pointer to the entry if found.
 * @return int, error code
 */
int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out);

/* *************************************************** *
 * TODO WEEK 06                                        *
 * *************************************************** */
/**
 * @brief Writes the already encrypted value at the end of the CKVS database,
 * then updates and overwrites the entry accordingly.
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param e (struct ckvs_entry *e) the entry to which the secret belongs
 * @param buf (const unsigned char*) the encrypted value to write
 * @param buflen (uint64_t) the length of buf
 * @return int, error code
 */
int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen);

/**
 * @brief Reads the file at filename, then allocates a buffer to dumps the file content into.
 * Not asked to students but helpful to have
 */
int read_value_file_content(const char *filename, char **buffer_ptr, size_t *buffer_size);


/**
 * @brief Helper function to close the file and free the buffer during the execution of read_value_file_content
 *
 * @param file (FILE**) file to close
 * @param buffer_ptr (char **) buffer to free
 */
void close_RVFC(FILE **file, char **buffer_ptr);

/* *************************************************** *
 * TODO WEEK 07                                        *
 * *************************************************** */
/**
 * @brief Creates a new entry in ckvs with the given (key, auth_key) pair, if possible.
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param key (const char*) the key of the new entry
 * @param auth_key (const struct ckvs_sha*) the auth_key of the new entry
 * @param e_out (struct ckvs_entry**) points to a pointer to an entry. Used to store the pointer to the created entry, if any.
 * @return int, error code
 */
int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out);


/**
 * @brief Delete the entry with the corresponding key and auth_key
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param key (const char*) the key of the entry to delete
 * @param auth_key (const struct ckvs_sha*) the auth_key of the entry to delete
 * @param e_out (struct ckvs_entry**) points to a pointer to an entry. Used to store the pointer to the created entry, if any.
 * @return int, error code
 */
int ckvs_delete_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out);


/**
 * @brief Compute the index of the given entry in ckvs->entries and write to the disk
 * @param e (struct ckvs_entry*) entry to be writen
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @return int, error code
 */
int compute_idx_and_write(struct ckvs_entry *e, struct CKVS *ckvs);




