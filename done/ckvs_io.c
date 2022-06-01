/**
 * @file ckvs_io.c
 * @brief c.f. ckvs_io.h
 */
#include <stdio.h>
#include <string.h>
#include "ckvs_utils.h"
#include "ckvs_crypto.h"
#include "ckvs.h"
#include "error.h"
#include <stdint.h>
#include <stdbool.h>
#include "ckvs_io.h"
#include <stdlib.h>
#include <openssl/sha.h>
#include "openssl/evp.h"

// ----------------------------------------------------------------------
/**
 * @brief Computes the hashkey of a the given key in ckvs.
 *
 * @param ckvs (struct CKVS*) the ckvs database to search
 * @param key (const char*) the key we want to compute the hash
 * @return uint32_t, the hashkey
 */
static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key) {
    //check pointers
    if (ckvs == NULL || key == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    ckvs_sha_t key_sha;
    uint32_t hashkey;

    //compute SHA256 of key
    SHA256((const unsigned char *) key, strlen(key), key_sha.sha);

    //copy the 4 first bytes
    memcpy(&hashkey, key_sha.sha, sizeof(uint32_t));

    //initialize the mask
    uint32_t mask = (uint32_t) ckvs->header.table_size - 1;

    //apply the mask and return the value
    return hashkey & mask;
}

// ----------------------------------------------------------------------
int ckvs_open(const char *filename, struct CKVS *ckvs) {
    //check pointers
    if (ckvs == NULL || filename == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialize the CKVS database
    memset(ckvs, 0, sizeof(struct CKVS));

    //open the file in read and write binary mode and assign it to the CKVS File
    FILE *file = NULL;
    file = fopen(filename, "r+b");
    if (file == NULL) {
        //error
        return ERR_IO;
    }
    ckvs->file = file;

    int a = read_header(ckvs);
    if (a != ERR_NONE) {
        ckvs_close(ckvs);
        return a;
    }

    ckvs->entries = calloc(ckvs->header.table_size, sizeof(ckvs_entry_t));
    if (ckvs->entries == NULL) {
        ckvs_close(ckvs);
        return ERR_OUT_OF_MEMORY;
    }

    size_t nb_ok3 = fread(ckvs->entries, sizeof(ckvs_entry_t), ckvs->header.table_size, file);
    if (nb_ok3 != ckvs->header.table_size) {
        //error
        ckvs_close(ckvs);
        return ERR_IO;
    }

    return ERR_NONE;
}

// ----------------------------------------------------------------------
void ckvs_close(struct CKVS *ckvs) {
    //check if the argument is valid, if so exit the function without doing anything
    if (ckvs == NULL) {
        //error
        return;
    }
    //close to file of the CKVS and make it point to NULL
    if (ckvs->file != NULL) {
        fclose(ckvs->file);
        ckvs->file = NULL;
    }
    //free entries and make it point to NULL
    if (ckvs->entries != NULL) {
        free(ckvs->entries);
        ckvs->entries = NULL;
    }
}

// ----------------------------------------------------------------------
int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
    //check pointeurs
    if (ckvs == NULL || key == NULL || auth_key == NULL || e_out == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //booleans created to follow if the key was found in the CKVS database, and if found, check if the auth_key is correct
    bool keyWasFound = false;
    bool authKeyIsCorrect = false;

    bool free_place_found = false;
    uint32_t free_index = 0;

    uint32_t idx = ckvs_hashkey(ckvs, key);

    //iterate over the table from index hashkey in linear probing
    uint32_t max_it = idx + ckvs->header.table_size;

    for (uint32_t i = idx; i < max_it; ++i) {
        // compute the index
        uint32_t j = i % ckvs->header.table_size;
        //check the key
        if (strncmp(ckvs->entries[j].key, key, CKVS_MAXKEYLEN) == 0) {
            keyWasFound = true;
            //check the auth_key
            if (ckvs_cmp_sha(&ckvs->entries[j].auth_key, auth_key) == 0) {
                authKeyIsCorrect = true;
                *e_out = &ckvs->entries[j];
            }
            break;
            // for new check for an empty slot
        } else if (!free_place_found && ckvs->entries[j].key[0] == '\0') {
            free_place_found = true;
            free_index = j;
        }

    }

    if (!keyWasFound) {
        //the entry that can be given for new
        *e_out = &ckvs->entries[free_index];
        //error
        return ERR_KEY_NOT_FOUND;
    }
    if (!authKeyIsCorrect) {
        //error
        return ERR_DUPLICATE_ID;
    }

    return ERR_NONE;
}

// ----------------------------------------------------------------------
int read_value_file_content(const char *filename, char **buffer_ptr, size_t *buffer_size) {
    //check pointers
    if (filename == NULL || buffer_ptr == NULL || buffer_size == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //create and open file
    FILE *file = NULL;
    file = fopen(filename, "rb"); //open in read binary mode
    if (file == NULL) {
        //error
        return ERR_IO;
    }
    //place the pointer at the end of the file and check errors
    int err = fseek(file, 0, SEEK_END);
    if (err != ERR_NONE) {
        //error
        if (file != NULL) {
                //close it
                fclose(file);
                file = NULL;
            }
        return ERR_IO;
    }

    //affect the string's length
    long int size_temp = ftell(file);
    if (size_temp == -1) {
        //error
        if (file != NULL) {
            //close it
            fclose(file);
            file = NULL;
        }
        return ERR_IO;
    }
    size_t size = (size_t) size_temp;

    //place the pointer at the beginning of the file back
    err = fseek(file, 0, SEEK_SET);
    if (err != ERR_NONE) {
        if (file != NULL) {
            //close it
            fclose(file);
            file = NULL;
        }
        return ERR_IO;
    }

    //create a buffer and check errors
    *buffer_ptr = calloc(size + 1, sizeof(char)); //so the '\0' char fits
    if (*buffer_ptr == NULL) {
        //error
        if (file != NULL) {
            //close it
            fclose(file);
            file = NULL;
        }

        return ERR_OUT_OF_MEMORY;
    }

    //read file and check errors
    size_t nb = fread(*buffer_ptr, sizeof(char), size, file);
    if (nb != size) {
        //error
        if (file != NULL) {
            //close it
            fclose(file);
            file = NULL;
        }
        free(*buffer_ptr);
        *buffer_ptr = NULL;
        return ERR_IO;
    }
    *buffer_size = size + 1; //update the buffer size to have the place for the final '\0'

    //close the opened file and finish
    fclose(file);
    file = NULL;
    return ERR_NONE;
}


// ----------------------------------------------------------------------
int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx) { //TODO : add a fflush(entry) after the fwrite ?
    //check ckvs pointer and validity of idx value
    if (ckvs == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }
    //place the pointer on the file on the right place and check errors
    int err = fseek(ckvs->file, (long int) (idx * sizeof(struct ckvs_entry) + sizeof(ckvs_header_t)), SEEK_SET);
    if (err != ERR_NONE) {
        //error
        return ERR_IO;
    }

    //write the entry and check errors
    size_t nb2 = fwrite(&ckvs->entries[idx], sizeof(ckvs_entry_t), 1, ckvs->file);
    if (nb2 != 1) {
        //error
        return ERR_IO;
    }
    return ERR_NONE;
}

// ----------------------------------------------------------------------
int ckvs_write_updated_header_to_disk(struct CKVS *ckvs) {
    //check ckvs pointer
    if (ckvs == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //place the pointer on the file on the right place and check errors
    int err = fseek(ckvs->file, (long int) (sizeof(ckvs->header.header_string) + 3 * sizeof(uint32_t)), SEEK_SET);
    if (err != ERR_NONE) {
        //error
        return ERR_IO;
    }

    //write the new number of entries in the header and check errors
    size_t nb2 = fwrite(&ckvs->header.num_entries, sizeof(uint32_t), 1, ckvs->file);
    if (nb2 != 1) {
        //error
        return ERR_IO;
    }
    return ERR_NONE;
}

// ----------------------------------------------------------------------
int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen) {
    //check pointers
    if (ckvs == NULL || e == NULL || buf == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }
    //to place the pointer at the end of the ckvs file
    int err = fseek(ckvs->file, 0, SEEK_END);
    if (err != ERR_NONE) {
        //error
        return ERR_IO;
    }

    //to assign the new values of c2, value_off and value_len
    e->value_len = buflen;
    e->value_off = (size_t) ftell(ckvs->file);

    //write at the end of the ckvs file the encrypted value
    size_t nb_ok = fwrite(buf, sizeof(char), buflen, ckvs->file);
    if (nb_ok != buflen) {
        //error
        return ERR_IO;
    }
    //flush to be sure
    err = fflush(ckvs->file);
    if (err != ERR_NONE) {
        //error
        return ERR_IO;
    }

    return compute_idx_and_write(e, ckvs);
}

// ----------------------------------------------------------------------
int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
    //check pointers
    if (ckvs == NULL || key == NULL || auth_key == NULL || e_out == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //verify that the entry can be added i.e. that there is still space in the table
    if (ckvs->header.threshold_entries <= ckvs->header.num_entries) {
        //error
        return ERR_MAX_FILES;
    }


    //to find the right entry in the database to place the entry
    int err = ckvs_find_entry(ckvs, key, auth_key, e_out);
    if (err != ERR_KEY_NOT_FOUND) {
        //error if an entry with the same key is found
        return err == ERR_NONE ? ERR_DUPLICATE_ID : err;
    }
    //associate the key to this entry
    strncpy((char *) &((*e_out)->key), key, CKVS_MAXKEYLEN);

    //associate the auth_key
    (*e_out)->auth_key = *auth_key;

    err = compute_idx_and_write(*e_out, ckvs);
    if (err != ERR_NONE) {
        return err;
    }

    //add one to the number of entries
    ckvs->header.num_entries += 1;

    //write the change in the header for the number of entries in the file
    err = ckvs_write_updated_header_to_disk(ckvs);
    if (err != ERR_NONE) {
        return err;
    }

    return ERR_NONE;
}

//--------------------------------------------------------------------------------------------
int ckvs_delete_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
    //check pointers
    if (ckvs == NULL || key == NULL || auth_key == NULL || e_out == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //to find the right entry in the database to delete it
    int err = ckvs_find_entry(ckvs, key, auth_key, e_out);
    if (err != ERR_NONE) {
        //error
        return err;
    }
    //associate the key to this entry
    strncpy((char *) &((*e_out)->key), key, CKVS_MAXKEYLEN);

    //associate the auth_key
    (*e_out)->auth_key = *auth_key;

    memset(*e_out,0, sizeof(ckvs_entry_t));
    err = compute_idx_and_write(*e_out, ckvs);
    if (err != ERR_NONE) {
        return err;
    }

    //remove one to the number of entries
    ckvs->header.num_entries -= 1;

    //write the change in the header for the number of entries in the file
    err=ckvs_write_updated_header_to_disk(ckvs);
    if (err != ERR_NONE) {
        return err;
    }

    return ERR_NONE;
}
//-------------------------------------------------------------------------------------

int compute_idx_and_write(struct ckvs_entry *e, struct CKVS *ckvs) {
    if (e == NULL || ckvs == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    //to modify the right entry in the ckvs table, index is obtained by subtracting the pointers
    uint32_t idx = (uint32_t)(e - &ckvs->entries[0]);

    return ckvs_write_entry_to_disk(ckvs, idx);
}

//----------------------------------------------------------------------
int read_header(CKVS_t *ckvs) {
    //check pointers
    if (ckvs == NULL || ckvs->file == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    //read the header and that it was well-read
    char header_str[CKVS_HEADERSTRINGLEN];
    size_t nb_ok = fread(header_str, sizeof(char), CKVS_HEADERSTRINGLEN, ckvs->file);
    if (nb_ok != CKVS_HEADERSTRINGLEN) {
        //error
        return ERR_IO;
    }
    //read the infos and that they were well-read
    uint32_t infos[CKVS_UINT32_T_ELEMENTS] = {0};
    size_t nb_ok2 = fread(infos, sizeof(uint32_t), 4, ckvs->file);
    if (nb_ok2 != CKVS_UINT32_T_ELEMENTS) {
        //error
        return ERR_IO;
    }
    //check that the header start with the good prefix
    if (strncmp(CKVS_HEADERSTRING_PREFIX, header_str, strlen(CKVS_HEADERSTRING_PREFIX)) != 0) {
        //error
        ckvs_close(ckvs);
        return ERR_CORRUPT_STORE;
    }

    if (infos[0] != 1) {
        //error
        return ERR_CORRUPT_STORE;
    }

    //check that the table has a size power of 2
    int a = check_pow_2(infos[1]);
    if (a != ERR_NONE) {
        return a;
    }

    //construct the header now that every field is safe
    ckvs_header_t header = {
            .version           =infos[0],
            .table_size        =infos[1],
            .threshold_entries =infos[2],
            .num_entries       =infos[3]
    };
    strcpy(header.header_string, header_str);
    ckvs->header = header;

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

//----------------------------------------------------------------------
int encrypt_secret(ckvs_memrecord_t *ckvs_mem, const char *set_value, unsigned char **encrypted, size_t *length) {
    //check pointers
    if (ckvs_mem == NULL || set_value == NULL || encrypted == NULL || length == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //encrypt set_value content (the +1 is for the final 0 not taken into account by strlen)
    *length = strlen(set_value) + 1 + EVP_MAX_BLOCK_LENGTH;
    *encrypted = calloc(*length, sizeof(unsigned char));
    if (*encrypted == NULL) {
        //error
        free_sve(encrypted, length);
        return ERR_OUT_OF_MEMORY;
    }
    int err = ckvs_client_crypt_value(ckvs_mem, ENCRYPTION, (const unsigned char *) set_value, strlen(set_value) + 1,
                                      *encrypted, length);
    if (err != ERR_NONE) {
        //error
        free_sve(encrypted, length);
        return err;
    }

    return ERR_NONE;
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
