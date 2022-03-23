/**
 * @file ckvs_local.c
 * @brief
 *
 * @author A. Troussard
 */
#include <stdio.h>
#include <string.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "error.h"
#include <stdint.h>
#include "ckvs_io.h"
#include "ckvs_crypto.h"


/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 * DO NOT FORGET TO USE pps_printf to print the header/entries!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @return int, an error code
 */
int ckvs_local_stats(const char *filename){
    struct CKVS ckvs;
    memset(&ckvs,0, sizeof(struct CKVS));
    int r = ckvs_open(filename,&ckvs);
    if (r!=ERR_NONE){
        return r;
    }

    print_header(&(ckvs.header));

    for (int i=0;i<CKVS_FIXEDSIZE_TABLE;i++){
        if(strlen(ckvs.entries[i].key)!=0){
            print_entry(&ckvs.entries[i]);
        }
    }
    return ERR_NONE;

}


/**
 * @brief Opens the CKVS database at the given filename and executes the 'get' command,
 * ie. fetches, decrypts and prints the entry corresponding to the key and password.
 * DO NOT FORGET TO USE pps_printf to print to value!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @param key (const char*) the key of the entry to get
 * @param pwd (const char*) the password of the entry to get
 * @return int, an error code
 */
int ckvs_local_get(const char *filename, const char *key, const char *pwd){
    struct CKVS ckvs;
    memset(&ckvs,0, sizeof(struct CKVS));
    int r = ckvs_open(filename,&ckvs);
    if (r!=ERR_NONE){
        return r;
    }
    ckvs_memrecord_t ckvs_mem;
    memset(&ckvs_mem,0, sizeof(ckvs_memrecord_t));

    ckvs_client_encrypt_pwd(&ckvs_mem,key,pwd);

    print_SHA("Buffer",&ckvs_mem.stretched_key);

    //print_SHA("Buffer",ckvs_mem.stretched_key);



    return ERR_NONE;
}


