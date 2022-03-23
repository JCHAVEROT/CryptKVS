#include <stdio.h>
#include <string.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "error.h"
#include <stdint.h>
#include "ckvs_io.h"
#include "ckvs.h"


int ckvs_open(const char *filename, struct CKVS *ckvs) {
    //empty ckvs
    memset(ckvs,0, sizeof(struct CKVS));


    //open the file
    if (filename == NULL) return ERR_INVALID_ARGUMENT;
    FILE *file = NULL;
    file = fopen(filename, "r+b");
    if (file == NULL) {
        return ERR_IO;
    }
    ckvs->file=file;


    // read the header
    char header_str[CKVS_HEADERSTRINGLEN];
    size_t nb_ok = fread(header_str, sizeof(char), CKVS_HEADERSTRINGLEN, file);
    if (nb_ok != CKVS_HEADERSTRINGLEN) {
        fclose(file);
        return ERR_IO;
    }

    uint32_t infos[CKVS_UINT32_T_ELEMENTS]= {0};
    size_t nb_ok2 = fread(infos, sizeof(uint32_t), 4, file);
    if (nb_ok2 != CKVS_UINT32_T_ELEMENTS) {
        fclose(file);
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
    ckvs_header_t header={
            .version           =infos[0],
            .table_size        =infos[1],
            .threshold_entries =infos[2],
            .num_entries       =infos[3]
    };

    strcpy(header.header_string,header_str);
    ckvs->header= header;

    if(ckvs->header.table_size!=CKVS_FIXEDSIZE_TABLE) { //For now but to be deleted later
        fclose(file);
        return ERR_CORRUPT_STORE;
    }





    size_t nb_ok3 = fread(ckvs->entries, sizeof(ckvs_entry_t), CKVS_FIXEDSIZE_TABLE, file);
    if (nb_ok3 != CKVS_FIXEDSIZE_TABLE) {
        fclose(file);
        return ERR_IO;
    }


    return ERR_NONE;


}

void ckvs_close(struct CKVS *ckvs){
    if (ckvs->file!=NULL) fclose(ckvs->file);
}

int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out){
    if (ckvs == NULL || key == NULL || auth_key == NULL || e_out == NULL) {
        // Error
        return ERR_INVALID_ARGUMENT;
    }
    bool keyWasFound = false;
    bool authKeyIsCorrect = false;
    for (int i = 0 ; i < CKVS_FIXEDSIZE_TABLE ; ++i) {
        if (strcmp(ckvs->entries[i].key, key) == 0) {
            keyWasFound = true;
            if (ckvs_cmp_sha(&ckvs->entries[i].auth_key, auth_key) == 0) {
                authKeyIsCorrect = true;
                *e_out = &ckvs->entries[i];
            }
            break;
        }
    }

    if (!keyWasFound) {
        // Error
        return ERR_KEY_NOT_FOUND;
    }
    if (!authKeyIsCorrect) {
        // Error
        return ERR_DUPLICATE_ID;
    }

    return ERR_NONE;
}

