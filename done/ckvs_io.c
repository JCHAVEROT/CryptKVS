/**
 * @file ckvs_io.c
 * @brief c.f. ckvs_io.h
 */
#include <stdio.h>
#include <string.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "ckvs_crypto.h"
#include "error.h"
#include <stdint.h>
#include <stdbool.h>
#include "ckvs_io.h"
#include <stdlib.h>
#include <openssl/sha.h>

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

    //read the header and that it was well read
    char header_str[CKVS_HEADERSTRINGLEN];
    size_t nb_ok = fread(header_str, sizeof(char), CKVS_HEADERSTRINGLEN, file);
    if (nb_ok != CKVS_HEADERSTRINGLEN) {
        //error
        fclose(file);
        return ERR_IO;
    }
    //read the infos and that they were well read
    uint32_t infos[CKVS_UINT32_T_ELEMENTS] = {0};
    size_t nb_ok2 = fread(infos, sizeof(uint32_t), 4, file);
    if (nb_ok2 != CKVS_UINT32_T_ELEMENTS) {
        //error
        fclose(file);
        return ERR_IO;
    }
    //check that the header start with the good prefix
    if (strncmp(CKVS_HEADERSTRING_PREFIX, header_str, strlen(CKVS_HEADERSTRING_PREFIX)) != 0) {
        //error
        fclose(file);
        return ERR_CORRUPT_STORE;
    }

    if (infos[0] != 1) {
        //error
        fclose(file);
        return ERR_CORRUPT_STORE;
    }

    //check that the table has a size power of 2
    uint32_t table_size = infos[1];
    while (table_size >= 2) {
        if (table_size % 2 != 0) break;
        table_size = table_size / 2;
    }
    if (table_size != 1) {
        //error
        fclose(file);
        return ERR_CORRUPT_STORE;
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

    //For now but to be modified later
    if (ckvs->header.table_size != CKVS_FIXEDSIZE_TABLE) {
        //error
        fclose(file);
        return ERR_CORRUPT_STORE;
    }

    size_t nb_ok3 = fread(ckvs->entries, sizeof(ckvs_entry_t), CKVS_FIXEDSIZE_TABLE, file);
    if (nb_ok3 != CKVS_FIXEDSIZE_TABLE) {
        //error
        fclose(file);
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
    }
    ckvs->file = NULL;
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

    bool free_place_found =false;
    uint32_t free_index=0;

    uint32_t hashkey = ckvs_hashkey(ckvs, key);
    uint32_t idx = hashkey % (ckvs->header.table_size - 1);
    //pps_printf("KEY : %s \n", key);
    //iterate over the table from index hashkey in linear probing
    for (uint32_t i = idx; i < idx+ckvs->header.table_size; ++i) {
        if (strncmp(ckvs->entries[idx].key, key, CKVS_MAXKEYLEN) == 0) {
            keyWasFound = true;
            if (ckvs_cmp_sha(&ckvs->entries[idx].auth_key, auth_key) == 0) {
                authKeyIsCorrect = true;
                *e_out = &ckvs->entries[idx];
            }
            break;
        }else if (!free_place_found && ckvs->entries[i].key[0] == '\0'){
            free_place_found=true;
            free_index=i;
        }

    }


   /* while (ckvs->entries[idx].key[0] != '\0') {
        //pps_printf("index : %u\n", idx);
        //print_entry(&ckvs->entries[idx]);

        idx = (idx + 1) % (ckvs->header.table_size - 1);
    }*/

    if (!keyWasFound) {
        //the entry that can be given a new one
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
        return ERR_IO;
    }

    //affects the string's length
    size_t size = (size_t) ftell(file);

    //places the pointer at the beginning of the file back
    err = fseek(file, 0, SEEK_SET);
    if (err != ERR_NONE) {
        return ERR_IO;
    }

    //create a buffer and check errors
    *buffer_ptr = calloc(size + 1, sizeof(char)); //so the '\0' char fits
    if (*buffer_ptr == NULL) {
        //error
        return ERR_OUT_OF_MEMORY;
    }

    //read file and check errors
    size_t nb = fread(*buffer_ptr, sizeof(char), size, file);
    if (nb != size) {
        //error
        return ERR_IO;
    }
    *buffer_size = size + 1; //update the buffer size to have the place for the final '\0'
    (*buffer_ptr)[size] = '\0'; //to add the final '\0'

    //close the opened file and finish
    fclose(file);
    return ERR_NONE;
}

// ----------------------------------------------------------------------
int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx) {
    //check ckvs pointer and validity of idx value
    if (ckvs == NULL || (idx >= CKVS_FIXEDSIZE_TABLE)) {
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

    //write at the end of the ckvs file the encrypted value to writes
    size_t nb_ok = fwrite(buf, sizeof(char), buflen, ckvs->file);
    if (nb_ok != buflen) {
        //error
        return ERR_IO;
    }
    err = fflush(ckvs->file);
    if (err != ERR_NONE) {
        //error
        return ERR_IO;
    }

    //to modify the right entry in the ckvs table, index is obtained by substracting the pointers
    uint32_t idx = (uint32_t)(e - &ckvs->entries[0]);

    //modify the entry in the disk
    err = ckvs_write_entry_to_disk(ckvs, idx);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    return ERR_NONE;
}

int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
    //check pointers
    if (ckvs == NULL || key == NULL || auth_key == NULL || e_out == NULL) {
        //error
        pps_printf("%s\n", "error 1");
        return ERR_INVALID_ARGUMENT;
    }

    //verify an entry can be added
    if (ckvs->header.threshold_entries <= ckvs->header.num_entries) {
        //error
        pps_printf("%s\n", "error 2");
        return ERR_MAX_FILES;
    }

    ckvs_entry_t* new_entry_in_table = *e_out;
    //to find the right entry in the database with the key and the auth_key latterly computed
    int err = ckvs_find_entry(ckvs, key, auth_key, &new_entry_in_table);
    if (err != ERR_KEY_NOT_FOUND) {
        //error if an entry with this particular key is found
        pps_printf("%s\n", "error 3");
        return err == ERR_NONE ? ERR_DUPLICATE_ID : err;
    }

    //copy the new entry content in the right entry in the table
    memcpy(new_entry_in_table,*e_out, sizeof(ckvs_entry_t));

    //to modify the right entry in the ckvs table, its index is obtained by substracting the pointers
    uint32_t idx = (uint32_t)(new_entry_in_table - &ckvs->entries[0]);

    err = ckvs_write_entry_to_disk(ckvs, idx);
    if (err != ERR_NONE) {
        //error
        pps_printf("%s\n", "error 4");
        return err;
    }

    //add one to the number of entries
    ckvs->header.num_entries += 1;

    //write the change in the header for the number of entries in the file
    ckvs_write_updated_header_to_disk(ckvs);

    return ERR_NONE;
}

static uint32_t ckvs_hashkey(struct CKVS *ckvs, const char *key) {
    //check pointers
    if (ckvs == NULL || key == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    ckvs_sha_t key_sha;
    uint32_t hashkey;

    //compute SHA256 of key
    SHA256((unsigned char *) key, strlen(key), key_sha.sha);
    //copy the 4 first bytes
    /*hashkey = (uint32_t) key_sha.sha[0] << 3 * 8 |
              (uint32_t) key_sha.sha[1] << 2 * 8 |
              (uint32_t) key_sha.sha[2] << 8 |
              (uint32_t) key_sha.sha[3];*/
    memcpy(&hashkey, key_sha.sha , 4);
    //pps_printf("key : 0x%x\n", hashkey);
    //the mask
    uint32_t mask = (uint32_t) ckvs->header.table_size - 1;
    //pps_printf("mask : 0x%02x\n", mask);


    //pps_printf("masked : 0x%02x\n", hashkey & mask);
    //apply the mask and return the value
    return hashkey & mask;
}