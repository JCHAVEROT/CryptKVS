/**
 * @file ckvs_local.c
 * @brief c.f. ckvs_local.h
 *
 * @author A.Troussard, J.Chaverot
 */
#include <stdio.h>
#include <string.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "error.h"
#include <stdint.h>
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "util.h"
#include "openssl/evp.h"
#include <ctype.h>
// ----------------------------------------------------------------------
int ckvs_local_stats(const char *filename) {
    //check if the argument is valid
    if (filename == NULL) return ERR_INVALID_ARGUMENT;
    //initialiaze the struct
    struct CKVS ckvs;
    memset(&ckvs,0, sizeof(struct CKVS));
    //open the filename and listen to errors
    int r = ckvs_open(filename,&ckvs);
    if (r!=ERR_NONE){
        return r;
    }
    //to print the header of the ckvs read from the file
    print_header(&(ckvs.header));

    //to print the entries of the ckvs read from the file
    for (int i=0;i<CKVS_FIXEDSIZE_TABLE;i++){
        if(strlen(ckvs.entries[i].key)!=0){
            print_entry(&ckvs.entries[i]);
        }
    }

    return ERR_NONE;
}
// ----------------------------------------------------------------------
int ckvs_local_get(const char *filename, const char *key, const char *pwd) {
    //check if the arguments are valid
    if (key == NULL || pwd == NULL || filename == NULL) return ERR_INVALID_ARGUMENT;

    //initialize the struct
    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(struct CKVS));

    //open the file
    int err = ckvs_open(filename,&ckvs);
    if (err != ERR_NONE) {
        // Error
        ckvs_close(&ckvs);
        return err;
    }
    //initialize the struct ckvs_memrecord_t
    ckvs_memrecord_t ckvs_mem;
    memset(&ckvs_mem, 0, sizeof(ckvs_memrecord_t));

    //to generate in particular the auth_key and c1 and store them in ckvs_mem
    err = ckvs_client_encrypt_pwd(&ckvs_mem, key, pwd);

    if (err != ERR_NONE) {
        // Error
        ckvs_close(&ckvs);
        return err;
    }

    //initialize the struct ckvs_entry_t
    ckvs_entry_t* ckvs_out;
    memset(&ckvs_out, 0, sizeof(ckvs_entry_t*));

    //to find the right entry in the database with the key and the auth_key latterly computed
    err = ckvs_find_entry(&ckvs, key, &ckvs_mem.auth_key, &ckvs_out);

    if (err != ERR_NONE) {
        // Error
        ckvs_close(&ckvs);
        return err;
    }

    //now we have the entry and hence c2, to compute the masterkey
    err = ckvs_client_compute_masterkey(&ckvs_mem, &ckvs_out->c2);
    if (err != ERR_NONE) {
        // Error
        ckvs_close(&ckvs);
        return err;
    }

    //to make the pointer lead to the beginning of the encrypted secret
    fseek(ckvs.file, (long int) ckvs_out->value_off, SEEK_SET);

    //initialize the string where the encrypted secret will be stored
    unsigned char encrypted[ckvs_out->value_len];
    //to read the encrypted secret
    size_t nb_ok = fread(encrypted, sizeof(unsigned char), ckvs_out->value_len, ckvs.file);
    if (nb_ok != ckvs_out->value_len) {
        ckvs_close(&ckvs);
        return ERR_IO;
    }
    //initialize the string where the decrypted secret will be stored
    size_t decrypted_len = ckvs_out->value_len + EVP_MAX_BLOCK_LENGTH;
    unsigned char decrypted[decrypted_len];
    //decrypts the the string with the secret with in particular the master_key stored in ckvs_mem
    err = ckvs_client_crypt_value(&ckvs_mem, 0, encrypted, ckvs_out->value_len, decrypted,
                                       &decrypted_len);
    if (err != ERR_NONE) {
        // Error
        ckvs_close(&ckvs);
        return err;
    }
    //check if we have to end the lecture
    for (size_t i = 0; i < strlen((char*) decrypted); ++i) {

        if ((iscntrl(decrypted[i])&& decrypted[i]!='\n')) break;
        pps_printf("%c",decrypted[i]);
    }

    //close the CKVS database at filename since done decrypting
    ckvs_close(&ckvs);

    return ERR_NONE;
}


