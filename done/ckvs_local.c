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
#include "ckvs_io.c"


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

int ckvs_local_get(const char *filename, const char *key, const char *pwd){
    printf("File: %s, Key : %s, Password: %s",filename,key,pwd);
    return ERR_NONE;
}


