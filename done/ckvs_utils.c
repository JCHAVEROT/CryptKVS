/**
 * @file ckvs_utils.c
 * @brief c.f. ckvs_utils.h
 */
#include <stdio.h>
#include <stdlib.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "util.h"
#include <inttypes.h>
#include "error.h"
#include <json-c/json.h>

// ----------------------------------------------------------------------
void print_header(const struct ckvs_header *header) {
    pps_printf("CKVS Header type       : %s\n", header->header_string);
    pps_printf("CKVS Header version    : %"  PRIu32 "\n", header->version);
    pps_printf("CKVS Header table_size : %"  PRIu32 "\n", header->table_size);
    pps_printf("CKVS Header threshold  : %"  PRIu32 "\n", header->threshold_entries);
    pps_printf("CKVS Header num_entries: %"  PRIu32 "\n", header->num_entries);
    return;
}

// ----------------------------------------------------------------------
void print_entry(const struct ckvs_entry *entry) {
    pps_printf("    %s   : " STR_LENGTH_FMT(CKVS_MAXKEYLEN) "\n", "Key", entry->key);
    pps_printf("    Value : off %" PRIu64  " len %" PRIu64 "\n", entry->value_off, entry->value_len);
    print_SHA("    Auth  ", &entry->auth_key);
    print_SHA("    C2    ", &entry->c2);
    return;
}

// ----------------------------------------------------------------------
void print_SHA(const char *prefix, const struct ckvs_sha *sha) {
    //check pointers
    if (prefix == NULL || sha == NULL) {
        //error
        return;
    }

    //initialize buffer of length SHA256_PRINTED_STRLEN and convert the SHA into string and print it
    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
    return;
}

// ----------------------------------------------------------------------
void hex_encode(const uint8_t *in, size_t len, char *buf) {
    //check pointers
    if (in == NULL || buf == NULL) {
        //error
        return;
    }

    //put in 'buf' the 'in' input string after converting it into printable hexadecimal
    for (size_t i = 0; i < len; ++i) {
        sprintf(&buf[2 * i], "%02x", in[i]);
    }

    return;
}

// ----------------------------------------------------------------------
void SHA256_to_string(const struct ckvs_sha *sha, char *buf) {
    //check pointers
    if (sha == NULL || buf == NULL) {
        //error
        return;
    }
    //call the function that encodes in hexadecimal
    hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);

    return;
}

// ----------------------------------------------------------------------
int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b) {
    //call the function that compares two byte strings
    return memcmp(a->sha, b->sha, SHA256_DIGEST_LENGTH);
}

// ----------------------------------------------------------------------
int hex_decode(const char *in, uint8_t *buf) {
    //check pointers
    if (in == NULL || buf == NULL) {
        //error
        return -1;
    }

    char temp[3] = {0};
    char* endptr = NULL;
    size_t half_size = strlen(in) / 2;

    size_t j = 0;
    //if odd size use the first element alone
    if (strlen(in) % 2 == 1) {
        strncpy(temp, &in[0], 1);
        uint64_t result = strtoul(temp, &endptr, 16);
        buf[0] = (uint8_t) result;
        //to shift for the main loop
        j = 1;
    }

        for (size_t i = 0; i < half_size; i++) {
            strncpy(temp, &in[2*i + j], 2);
            uint64_t result = strtoul(temp, &endptr, 16);
            buf[i+j] = (uint8_t) result;
        }

    return (int) half_size + j;
}

// ----------------------------------------------------------------------
int SHA256_from_string(const char *in, struct ckvs_sha *sha) {
    //check pointers
    if (in == NULL || sha == NULL) {
        //error
        return -1;
    }
    //call the function that decodes from hexadecimal
    int err = hex_decode(in, sha->sha);
    if (err == -1) {
        return err;
    }

    return ERR_NONE;
}

// ----------------------------------------------------------------------
int get_err(char* error) {
    for (size_t i = 1; i < ERR_NB_ERR; ++i) {
        if (strncmp(error, ERR_MESSAGES[i], strlen(ERR_MESSAGES[i]))==0 ) {
            return (int) i;
        }
    }

    return ERR_PROTOCOL;
}


//----------------------------------------------------------------------
void free_sve(unsigned char **sve, size_t *sve_length) {
    if (sve != NULL && *sve != NULL) {
        free(*sve);
        *sve = NULL;
    }
    if (sve_length != NULL) *sve_length = 0;
}

//----------------------------------------------------------------------
void free_uc(unsigned char **a) {
    if (a != NULL) {
        if (*a != NULL) {
            free(*a);
            *a = NULL;
        }
    }
}

//----------------------------------------------------------------------
int add_string(struct json_object *obj, const char *key, const char *val) {
    //check pointers
    if (obj == NULL || key == NULL || val == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    return json_object_object_add(obj, key, json_object_new_string(val));
}

//----------------------------------------------------------------------
int add_array(const struct json_object *obj, const char *key, const char *array[], size_t size) {
    //check pointers
    if (obj == NULL || key == NULL || array == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    struct json_object *arr = json_object_new_array();

    for (size_t i = 0; i < size; i++) {
        json_object_array_add(arr, json_object_new_string(array[i]));
    }

    return json_object_object_add((struct json_object *) obj, key, arr);
}

//----------------------------------------------------------------------
int add_int(struct json_object *obj, const char *key, int val) {
    //check pointers
    if (obj == NULL || key == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    return json_object_object_add(obj, key, json_object_new_int(val));
}

//----------------------------------------------------------------------
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

//----------------------------------------------------------------------
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

//----------------------------------------------------------------------
int check_pow_2(uint32_t table_size) {
    while (table_size >= 2) {
        if (table_size % 2 != 0) break;
        table_size = table_size / 2;
    }
    if (table_size != 1) {
        //error
        return ERR_CORRUPT_STORE;
    }
    return ERR_NONE;
}




