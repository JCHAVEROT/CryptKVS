/**
 * @file ckvs_utils.h
 * @brief binary-to-hexadedimal conversion routines
 *
 * Utilities to convert binary data into printable hexadecimal format and back.
 *
 * @author Edouard Bugnion
 */

#pragma once

#include <openssl/sha.h>
#include <json-c/json.h>



/**
 * @brief Holds data for a SHA256 hash (ie. 32B = 256b).
 */
struct __attribute__((packed, aligned(8))) ckvs_sha {
    unsigned char sha[SHA256_DIGEST_LENGTH];
};

typedef struct ckvs_sha ckvs_sha_t;


#define SHA256_PRINTED_STRLEN (SHA256_DIGEST_LENGTH*2+1)

#if defined CS212_TEST
// custom printf in tests
int pps_printf(const char* __restrict__ format, ...);
#else
// In normal use: pps_printf = printf
#define pps_printf printf
#endif


// defined in ckvs.h, declared here to avoid circular dependencies
struct ckvs_header;
struct ckvs_entry;

/* *************************************************** *
 * TODO WEEK 04                                        *
 * *************************************************** */
/**
 * @brief Prints the given header to the standard output,
 * see 04.stats.md for the exact output format.
 * DO NOT FORGET TO USE pps_printf !!!
 *
 * @param header (const struct ckvs_header*) the header to print
 */
void print_header(const struct ckvs_header *header);

/**
 * @brief Prints the given entry to the standard output,
 * see 04.stats.md for the exact output format.
 * DO NOT FORGET TO USE pps_printf !!!
 *
 * @param entry (const struct ckvs_entry*) the entry to print
 */
void print_entry(const struct ckvs_entry *entry);

/**
 * @brief Prints the given prefix and SHA (hex-encoded) to the standard output.
 * DO NOT FORGET TO USE pps_printf !!!
 *
 * @param prefix (const char*) the prefix to prepend to the SHA
 * @param sha (const struct ckvs_sha*) the SHA to print
 */
void print_SHA(const char *prefix, const struct ckvs_sha *sha);

/**
 * @brief Encodes a byte array into a printable hex-encoded string.
 *
 * @param in (const uint8_t*) pointer to the input byte buffer
 * @param len (size_t) length of the input byte buffer
 * @param buf (char*) pointer to the output char buffer,
 * assumed to be large enough to store the full representation (+ a null byte)
 *
 * @see hex_decode for the inverse operation
 */
void hex_encode(const uint8_t *in, size_t len, char *buf);

/**
 * @brief Encodes a ckvs_sha into its printable hex-encoded representation.
 *
 * @param sha (const struct ckvs_sha*) pointer to the input hash
 * @param buf (char*) pointer to the char buffer,
 * assumed to be large enough to store the full representation (+ a null byte)
 *
 * @see SHA256_from_string for the inverse operation
 */
void SHA256_to_string(const struct ckvs_sha *sha, char *buf);


/* *************************************************** *
 * TODO WEEK 05                                        *
 * *************************************************** */
/**
 * @brief Compares two SHA.
 *
 * @param a (const struct ckvs_sha*) the first SHA to compare
 * @param b (const struct ckvs_sha*) the second SHA to compare
 * @return int, a negative value if a < b ;
 * 0 if a == b ;
 * and a positive value if a > b.
 */
int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b);


/* *************************************************** *
 * TODO WEEK 10                                        *
 * *************************************************** */

/**
 * @brief Decodes a printable hex-encoded string into the corresponding value in a byte array.
 *
 * @param in (const char*) pointer to the input char array
 * @param buf (uint8_t*) pointer to the output byte buffer,
 * assumed to be large enough to store the decoded value.
 * @return int, the number of written bytes, or -1 in case of error
 *
 * @see hex_encode for the inverse operation
 */
int hex_decode(const char *in, uint8_t *buf);

/**
 * @brief Decodes a ckvs_sha from its printable hex-encoded representation.
 *
 * @param in (const char*) pointer to the char buffer
 * @param sha (struct ckvs_sha*) pointer to the output hash
 * @return int, the number of written bytes, or -1 in case of error
 *
 * @see SHA256_to_string for the inverse operation
 */
int SHA256_from_string(const char *in, struct ckvs_sha *sha);

/**
 * @brief Method used to retrieve the error code from a string.
 *
 * @param error (char*) the string
 * @return int, error code
 */
int get_err(char* error);



/**
 * @brief Auxiliary function to easily free set_value_encrypted's dynamic allocation
 *
 * @param sve (const char*)
 * @param sve_length (size_t)
 */
void free_sve(unsigned char **sve, size_t *sve_length);

/**
 * @brief Auxiliary function to easily free an unsigned char*
 *
 * @param a (unsigned char**) pointer to the unsigned char* to free
 */
void free_uc(unsigned char **a);

/**
 * @brief To add an inner json object associated to the key with value the given string.
 *
 * @param obj (struct json_object*) the main parent json object
 * @param key (const char*) the key associated to the string we add
 * @param val (char*) the string we add to the json object
 * @return int, error code
 */
int add_string(struct json_object *obj, const char *key, const char *val);

/**
 * @brief
 *
 * @param obj
 * @param key
 * @param array
 * @param size
 * @return
 */
int add_array(const struct json_object *obj, const char *key, const char *array[], size_t size);

/**
 * @brief To add an inner json object associated to the key with value the given integer.
 *
 * @param obj (struct json_object*) the main parent json object
 * @param key (const char*) the key associated to the integer we add
 * @param val (int) the integer we add to the json object
 * @return int, error code
 */
int add_int(struct json_object *obj, const char *key, int val);

/**
 * @brief To get the integer associated to the key from a json object.
 *
 * @param obj (const json_object*) the main json object we retrieve the information from
 * @param key (const char*) the key of the integer of interest
 * @param buf (char*) buffer used to store the computed integer
 * @return int, error code
 */
int get_int(const struct json_object *obj, const char *key, int *buf);

/**
 * @brief To get the usable string associated to the key from a json object.
 *
 * @param obj (const json_object*) the main json object we retrieve the information from
 * @param key (const char*) the key of the string of interest
 * @param buf (char*) buffer used to store the computed string
 * @return int, error code
 */
int get_string(const struct json_object *obj, const char *key, char *buf);

/**
 * @brief helper function to check if a uint32_t is a power of 2
 *
 * @param (uint32_t) table_size the uint32_t to check
 * @return int, error code
 */
int check_pow_2(uint32_t table_size);


