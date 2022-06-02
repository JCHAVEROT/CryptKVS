/**
 * @file ckvs_local.c
 * @brief c.f. ckvs_local.h
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "error.h"
#include <stdint.h>
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "util.h"
#include "openssl/evp.h"
#include "openssl/rand.h"
#include <ctype.h>
#include "ckvs_local.h"

// ----------------------------------------------------------------------
int ckvs_local_stats(const char *filename, int optargc, _unused char *optargv[]) {

    if (optargc > 0) return ERR_TOO_MANY_ARGUMENTS;
    //check if the pointeur is valid
    if (filename == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialiaze the struct ckvs
    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(struct CKVS));

    //open the filename and check errors
    int err = ckvs_open(filename, &ckvs);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //print the header of the ckvs read from the file
    print_header(&(ckvs.header));

    //print the entries of the ckvs read from the file
    for (int i = 0; i < CKVS_FIXEDSIZE_TABLE; i++) {
        if (strlen(ckvs.entries[i].key) != 0) {
            print_entry(&ckvs.entries[i]);
        }
    }
    //close the ckvs
    ckvs_close(&ckvs);

    return ERR_NONE;
}

// ----------------------------------------------------------------------
int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char *set_value) {
    //check if the arguments are valid
    if (key == NULL || pwd == NULL || filename == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialize the struct ckvs
    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(struct CKVS));

    //open the file
    int err = ckvs_open(filename, &ckvs);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //initialize the struct ckvs_memrecord_t
    ckvs_memrecord_t ckvs_mem;
    memset(&ckvs_mem, 0, sizeof(ckvs_memrecord_t));

    //to generate in particular the auth_key and c1 and store them in ckvs_mem
    err = ckvs_client_encrypt_pwd(&ckvs_mem, key, pwd);
    if (err != ERR_NONE) {
        // error
        ckvs_close(&ckvs);
        return err;
    }

    //initialize the struct ckvs_entry_t
    ckvs_entry_t *ckvs_out = NULL;

    //to find the right entry in the database with the key and the auth_key latterly computed
    err = ckvs_find_entry(&ckvs, key, &ckvs_mem.auth_key, &ckvs_out);
    if (err != ERR_NONE) {
        //error
        ckvs_close(&ckvs);
        return err;
    }

    //if in set mode, to generate randomly SHA256 of c2 so not to decrease entropy
    if (set_value != NULL) {
        err = RAND_bytes((unsigned char *) &(ckvs_out->c2.sha), SHA256_DIGEST_LENGTH);
        if (err != 1) {
            //error
            ckvs_close(&ckvs);
            return ERR_IO;
        }
    }

    //now we have the entry and hence c2, to compute the masterkey
    err = ckvs_client_compute_masterkey(&ckvs_mem, &(ckvs_out->c2));
    if (err != ERR_NONE) {
        // Error
        ckvs_close(&ckvs);
        return err;
    }

    //the get part
    if (set_value == NULL) {
        return do_get(&ckvs, ckvs_out, &ckvs_mem);
        //end get part
    } else {
        return do_set(&ckvs, ckvs_out, &ckvs_mem, set_value);
    }
}

//-----------------------------------------------------------------------
int do_get(CKVS_t *ckvs, ckvs_entry_t *ckvs_out, ckvs_memrecord_t *ckvs_mem) {
    if (ckvs_out->value_len > 0) {
        //make the pointer lead to the beginning of the encrypted secret
        int err = fseek(ckvs->file, (long int) ckvs_out->value_off, SEEK_SET);
        if (err != ERR_NONE) {
            //error
            ckvs_close(ckvs);
            return ERR_IO;
        }

        //initialize the string where the encrypted secret will be stored
        unsigned char *encrypted = calloc(ckvs_out->value_len, sizeof(unsigned char));
        if (encrypted == NULL) {
            return ERR_OUT_OF_MEMORY;
        }

        //read the encrypted secret
        size_t nb_ok = fread(encrypted, sizeof(unsigned char), ckvs_out->value_len, ckvs->file);
        if (nb_ok != ckvs_out->value_len) {
            //error
            ckvs_close(ckvs);
            free_uc(&encrypted);
            return ERR_IO;
        }

        //initialize the string where the decrypted secret will be stored
        size_t decrypted_len = ckvs_out->value_len + EVP_MAX_BLOCK_LENGTH;
        unsigned char *decrypted = calloc(decrypted_len, sizeof(unsigned char));

        if (decrypted == NULL) {
            ckvs_close(ckvs);
            free_uc(&encrypted);
            return ERR_OUT_OF_MEMORY;
        }

        //decrypts the string with the secret with in particular the master_key stored in ckvs_mem
        err = ckvs_client_crypt_value(ckvs_mem, DECRYPTION, encrypted, ckvs_out->value_len, decrypted,
                                      &decrypted_len);
        if (err != ERR_NONE) {
            // Error
            ckvs_close(ckvs);
            free_uc(&encrypted);
            free_uc(&decrypted);
            return err;
        }

        //check if we have to end the lecture
        for (size_t i = 0; i < decrypted_len; ++i) {
            if ((iscntrl(decrypted[i]) && decrypted[i] != '\n')) break;
            pps_printf("%c", decrypted[i]);
        }

        //close the CKVS database at filename since done decrypting
        ckvs_close(ckvs);
        free_uc(&encrypted);
        free_uc(&decrypted);
        decrypted = NULL;

        return ERR_NONE;
    } else {
        //error
        ckvs_close(ckvs);
        return ERR_NO_VALUE;
    }
}

int do_set(CKVS_t *ckvs, ckvs_entry_t *ckvs_out, ckvs_memrecord_t *ckvs_mem, const char *set_value) {
    //encrypt set_value content
    unsigned char* set_value_encrypted = NULL;
    size_t set_value_encrypted_length = 0;
    int err = encrypt_secret(ckvs_mem, set_value, &set_value_encrypted, &set_value_encrypted_length);
    if (err != ERR_NONE) {
        //error
        ckvs_close(ckvs);
        return err;
    }

    err = ckvs_write_encrypted_value(ckvs, ckvs_out, (const unsigned char *) set_value_encrypted,
                                     (uint64_t) set_value_encrypted_length);
    if (err != ERR_NONE) {
        //error
        ckvs_close(ckvs);
        free_sve(&set_value_encrypted, &set_value_encrypted_length);
        return err;
    }

    //close the file, free the pointer and finish
    ckvs_close(ckvs);
    free_sve(&set_value_encrypted, &set_value_encrypted_length);

    return ERR_NONE;
}

// ----------------------------------------------------------------------
int ckvs_local_get(const char *filename, int optargc, char *optargv[]) {
    if (optargc < 2) return ERR_NOT_ENOUGH_ARGUMENTS;
    if (optargc > 2) return ERR_TOO_MANY_ARGUMENTS;

    const char *key = optargv[0];
    const char *pwd = optargv[1];
    //check if the pointeurs are valid
    if (key == NULL || pwd == NULL || filename == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }
    //call the modularize getset function with NULL as set_value
    return ckvs_local_getset(filename, key, pwd, NULL);
}

// ----------------------------------------------------------------------
int ckvs_local_set(const char *filename, int optargc, char *optargv[]) {
    if (optargc < 3) return ERR_NOT_ENOUGH_ARGUMENTS;
    if (optargc > 3) return ERR_TOO_MANY_ARGUMENTS;

    const char *key = optargv[0];
    const char *pwd = optargv[1];
    const char *valuefilename = optargv[2];

    //check pointers
    if (filename == NULL || key == NULL || pwd == NULL || valuefilename == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialize buffer and its size
    char *buffer = NULL;
    size_t buffer_size = 0;

    //read file called filename and prints it in the buffer and check errors
    int err = read_value_file_content(valuefilename, &buffer, &buffer_size);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //called the modularized function ckvs_local_getset with the buffer
    err = ckvs_local_getset(filename, key, pwd, buffer);

    //free the buffer
    free(buffer);
    buffer = NULL;
    buffer_size = 0;

    return err;
}

int ckvs_local_new(const char *filename, int optargc, char *optargv[]) {

    if (optargc < 2) return ERR_NOT_ENOUGH_ARGUMENTS;
    if (optargc > 2) return ERR_TOO_MANY_ARGUMENTS;

    const char *key = optargv[0];
    const char *pwd = optargv[1];

    //check if the pointeurs are valid
    if (filename == NULL || key == NULL || pwd == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialiaze the struct ckvs
    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(struct CKVS));

    //open the filename and check errors
    int err = ckvs_open(filename, &ckvs);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //initialize the struct ckvs_memrecord_t
    ckvs_memrecord_t ckvs_mem;
    memset(&ckvs_mem, 0, sizeof(ckvs_memrecord_t));

    //initialize the pointer of a struct ckvs_entry_t for the new entry
    ckvs_entry_t *new_ckvs_entry = NULL;

    //verify is key is not too long
    if (strlen(key) > CKVS_MAXKEYLEN) {
        ckvs_close(&ckvs);
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //to generate in particular the auth_key and c1 and store them in ckvs_mem
    err = ckvs_client_encrypt_pwd(&ckvs_mem, key, pwd);
    if (err != ERR_NONE) {
        ckvs_close(&ckvs);
        // error
        return err;

    }

    //add the new entry to the table if possible
    err = ckvs_new_entry(&ckvs, key, &(ckvs_mem.auth_key), &new_ckvs_entry);
    if (err != ERR_NONE) {
        // error
        ckvs_close(&ckvs);
        return err;
    }

    //close the file and finish
    ckvs_close(&ckvs);

    return ERR_NONE;
}

int ckvs_local_delete(const char *filename, int optargc, char *optargv[]) {
    if (optargc < 2) return ERR_NOT_ENOUGH_ARGUMENTS;
    if (optargc > 2) return ERR_TOO_MANY_ARGUMENTS;

    const char *key = optargv[0];
    const char *pwd = optargv[1];

    //check if the pointeurs are valid
    if (filename == NULL || key == NULL || pwd == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialiaze the struct ckvs
    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(struct CKVS));

    //open the filename and check errors
    int err = ckvs_open(filename, &ckvs);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //initialize the struct ckvs_memrecord_t
    ckvs_memrecord_t ckvs_mem;
    memset(&ckvs_mem, 0, sizeof(ckvs_memrecord_t));

    //initialize the pointer of a struct ckvs_entry_t for the new entry
    ckvs_entry_t *new_ckvs_entry = NULL;

    //verify is key is not too long
    if (strlen(key) > CKVS_MAXKEYLEN) {
        ckvs_close(&ckvs);
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //to generate in particular the auth_key and c1 and store them in ckvs_mem
    err = ckvs_client_encrypt_pwd(&ckvs_mem, key, pwd);
    if (err != ERR_NONE) {
        ckvs_close(&ckvs);
        // error
        return err;

    }

    //add the new entry to the table if possible
    err = ckvs_delete_entry(&ckvs, key, &(ckvs_mem.auth_key), &new_ckvs_entry);
    if (err != ERR_NONE) {
        // error
        ckvs_close(&ckvs);
        return err;
    }

    //close the file and finish
    ckvs_close(&ckvs);

    return ERR_NONE;
}
