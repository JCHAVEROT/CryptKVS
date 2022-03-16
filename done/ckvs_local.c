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

/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 * DO NOT FORGET TO USE pps_printf to print the header/entries!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @return int, an error code
 */
int ckvs_local_stats(const char *filename){
    FILE* file=NULL;
    file= fopen(filename,"rb");
    if (file==NULL){
        printf("1");
        return ERR_IO;
    }
    char header_str[CKVS_HEADERSTRINGLEN];
    size_t nb_ok = fread(header_str, sizeof(char), CKVS_HEADERSTRINGLEN, file);
    if (nb_ok != CKVS_HEADERSTRINGLEN) {
        fclose(file);
        printf("2");
        return ERR_IO;
    }

    uint32_t infos[CKVS_UINT32_T_ELEMENTS]= {0};
    size_t nb_ok2 = fread(infos, sizeof(uint32_t), 4, file);
    if (nb_ok2 != CKVS_UINT32_T_ELEMENTS) {
        fclose(file);
        printf("3");
        return ERR_IO;
    }


    if(strncmp(CKVS_HEADERSTRING_PREFIX,header_str,strlen(CKVS_HEADERSTRING_PREFIX))!=0){
        fclose(file);
        return ERR_CORRUPT_STORE;
    }

    if (infos[0]!=1){
        fclose(file);
        return ERR_CORRUPT_STORE;
    }
    uint32_t table_size= infos[1];
    while (table_size>=2){
        if (table_size%2!=0) break;
        table_size=table_size/2;
    }
    if (table_size!=1) {
        fclose(file);
        return ERR_CORRUPT_STORE;
    }

    ckvs_header_t header= {

            .version           =infos[0],
            .table_size        =infos[1],
            .threshold_entries =infos[2],
            .num_entries       =infos[3]
    };
    strcpy(header.header_string,header_str);
    print_header(&header);/*TODO PRINT_HEADER*/

    if(header.table_size!=CKVS_FIXEDSIZE_TABLE) {
        fclose(file);
        return ERR_CORRUPT_STORE;
    }

    ckvs_entry_t entries[CKVS_FIXEDSIZE_TABLE];

    size_t nb_ok3 = fread(entries, sizeof(ckvs_entry_t), CKVS_FIXEDSIZE_TABLE, file);
    if (nb_ok3 != CKVS_FIXEDSIZE_TABLE) {
        fclose(file);
        //printf("4");
        return ERR_IO;
    }

    for (int i=0;i<CKVS_FIXEDSIZE_TABLE;i++){
        if(strlen(entries[i].key)!=0){
            print_entry(&entries[i]);
        }
    }

    fclose(file);
    return ERR_NONE;

}


